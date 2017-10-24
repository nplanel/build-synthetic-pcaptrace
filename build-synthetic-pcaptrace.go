package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	logger "log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var log = logger.New(os.Stdout, "", 0)

type Packet struct {
	data []byte
}

type Flow struct {
	ID       int64
	pcapInfo *PCAPInfo
}

func (b *SyntheticPcapTraceBuilder) newFlow(pinfo *PCAPInfo) *Flow {
	return &Flow{
		ID:       b.rand.Int63(),
		pcapInfo: pinfo,
	}
}

type PCAPFile struct {
	file   *os.File
	Reader *pcapgo.Reader
}

func (p *PCAPFile) Close() {
	p.file.Close()
}

func OpenPCAP(filename string) *PCAPFile {
	f, err := os.Open(filename)
	if err != nil {
		fmt.Printf("opening pcap file %s : %s", filename, err.Error())
		os.Exit(1)
	}

	r, err := pcapgo.NewReader(f)
	if err != nil {
		fmt.Printf("Error reading pcap file %s : %s", filename, err.Error())
		os.Exit(1)
	}
	p := &PCAPFile{file: f, Reader: r}
	return p
}

type PCAPInfo struct {
	Filename  string
	Packets   int64
	Bytes     int64
	Flows     int
	Gopackets []gopacket.Packet
}

type PCAPDatabase struct {
	templateDirectory string
	currentPcap       int
	db                []PCAPInfo
}

func NewPCAPDatabase(templateDirectory string) *PCAPDatabase {
	pcapDB := &PCAPDatabase{
		templateDirectory: templateDirectory,
	}
	pcapDB.init()
	return pcapDB
}

func (p *PCAPDatabase) pcapTemplateWalk(path string, info os.FileInfo, err error) error {
	if info.IsDir() {
		return nil
	}
	p.insert(path)
	return nil
}

func (p *PCAPDatabase) init() {
	filepath.Walk(p.templateDirectory, p.pcapTemplateWalk)
}

func (p *PCAPDatabase) insert(pcapFilename string) {
	packets := int64(0)
	bytes := int64(0)
	flows := make(map[uint64]bool)
	var gopackets []gopacket.Packet

	pcap := OpenPCAP(pcapFilename)
	for {
		data, _, err := pcap.Reader.ReadPacketData()
		if err != nil {
			if err != io.EOF {
				fmt.Printf("read packet error %s", err.Error())
			}
			break
		}

		packet := gopacket.NewPacket(data, pcap.Reader.LinkType(), gopacket.Default)
		ipv4 := packet.Layer(layers.LayerTypeIPv4)
		if ipv4 == nil {
			continue
		}
		flowHash := packet.LinkLayer().LinkFlow().FastHash() ^ packet.NetworkLayer().NetworkFlow().FastHash() ^ packet.TransportLayer().TransportFlow().FastHash()

		packets++
		bytes += int64(len(data))
		flows[flowHash] = true
		gopackets = append(gopackets, packet)
	}
	pcap.Close()

	info := PCAPInfo{
		Filename:  pcapFilename,
		Packets:   packets,
		Bytes:     bytes,
		Flows:     len(flows),
		Gopackets: gopackets,
	}
	p.db = append(p.db, info)
	log.Printf("Insert %s in database", pcapFilename)
}

func (p *PCAPDatabase) GetNext() *PCAPInfo {
	p.currentPcap = (p.currentPcap + 1) % len(p.db)
	return &p.db[p.currentPcap]
}

type SyntheticPcapTraceBuilder struct {
	GoalMbps                     int
	GoalAvgPacketSize            int
	GoalFlowRampUpDownPerSecond  int
	GoalFlowSteadyStatePerSecond int
	GoalSteadyStateSeconds       int

	maxPacketPerSecond int
	maxBytesPerSecond  int
	maxFlowsPerSecond  int
	maxFlows           int

	genLimitPackets int64
	genLimitFlows   int
	genLimitSeconds int64
	genLimitMB      int64

	generatedPackets int64
	generatedBytes   int64
	generatedSeconds int

	lastSecondPackets int
	lastSecondBytes   int
	lastSecondFlows   int

	rand              *rand.Rand
	startTime         time.Time
	currentPacketTime time.Time
	pcapDB            *PCAPDatabase
	pcapOUT           *pcapgo.Writer
	packets           []*Packet
}

func (b *SyntheticPcapTraceBuilder) updateMaxValues() {
	bytesPerSecond := ((b.GoalMbps * 1000000) / 8)
	b.maxPacketPerSecond = bytesPerSecond / b.GoalAvgPacketSize
	b.maxBytesPerSecond = bytesPerSecond
	b.maxFlowsPerSecond = b.GoalFlowRampUpDownPerSecond
	b.maxFlows = b.GoalFlowSteadyStatePerSecond

	log.Printf(
		"maxPacketPerSecond %d\n"+"maxBytesPerSecond %d\n"+"maxFlowsPerSecond %d\n"+"maxFlows %d\n",
		b.maxPacketPerSecond,
		b.maxBytesPerSecond,
		b.maxFlowsPerSecond,
		b.maxFlows)

}

func (b *SyntheticPcapTraceBuilder) flushPackets() {
	flushAt := b.currentPacketTime

	usec := 1000000.0 / len(b.packets)
	//	log.Printf("flush %d packets, usec per packet %d flush at %v", len(packets), usec, flushAt)
	for _, packet := range b.packets {
		data := packet.data
		ci := gopacket.CaptureInfo{
			CaptureLength: len(data),
			Length:        len(data),
			Timestamp:     b.currentPacketTime,
		}
		b.pcapOUT.WritePacket(ci, data)

		b.currentPacketTime = b.currentPacketTime.Add(time.Duration(usec) * time.Microsecond)
	}

	dt := b.currentPacketTime.Sub(flushAt)
	if dt < 1.0 {
		b.currentPacketTime.Add(dt)
	}

	b.lastSecondPackets = 0
	b.lastSecondBytes = 0
	b.lastSecondFlows = 0

}

func modifyIPv4(orig net.IP, f *Flow) net.IP {
	v := binary.BigEndian.Uint32(orig) ^ uint32(f.ID)
	ret := net.IP{0, 0, 0, 0}
	binary.BigEndian.PutUint32(ret, v)
	return ret
}

func (b *SyntheticPcapTraceBuilder) modifyIPLayer(packet *gopacket.Packet, f *Flow) *Packet {
	var newLayers []gopacket.SerializableLayer
	var ipv4 *layers.IPv4
	for _, l := range (*packet).Layers() {
		switch l.LayerType() {
		case layers.LayerTypeIPv4:
			ipv4, _ = l.(*layers.IPv4)
			ipv4.SrcIP = modifyIPv4(ipv4.SrcIP, f)
			ipv4.DstIP = modifyIPv4(ipv4.DstIP, f)
			newLayers = append(newLayers, ipv4)
			continue
		case layers.LayerTypeUDP:
			udp, _ := l.(*layers.UDP)
			udp.SetNetworkLayerForChecksum(ipv4)
		case layers.LayerTypeTCP:
			tcp, _ := l.(*layers.TCP)
			tcp.SetNetworkLayerForChecksum(ipv4)
		}
		newLayers = append(newLayers, l.(gopacket.SerializableLayer))
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buffer, options, newLayers...); err != nil {
		log.Fatalf("serialize new ipv4 error : %s", err.Error())
	}
	return &Packet{
		data: buffer.Bytes(),
	}
}

func (b *SyntheticPcapTraceBuilder) processPackets(f *Flow) {
	//	log.Printf("process %d packets", len(f.pcapInfo.Gopackets))
	b.packets = []*Packet{}
	for _, packet := range f.pcapInfo.Gopackets {
		newPacket := b.modifyIPLayer(&packet, f)
		packetSize := len(packet.Data())
		b.generatedPackets++
		b.generatedBytes += int64(packetSize)
		b.lastSecondPackets++
		b.lastSecondBytes += packetSize

		b.packets = append(b.packets, newPacket)

		if b.lastSecondPackets > b.maxPacketPerSecond || b.lastSecondBytes > b.maxBytesPerSecond {
			b.flushPackets()
			b.packets = []*Packet{}
		}
	}
}

func removeFlowTable(ft *map[int64]*Flow, n int) int {
	flows := 0
	i := 0
	for k, f := range *ft {
		if i == n {
			flows += f.pcapInfo.Flows
			delete(*ft, k)
		}
		i++
	}
	return flows
}

func lenFlowTable(ft *map[int64]*Flow) int {
	i := 0
	for _, f := range *ft {
		i += f.pcapInfo.Flows
	}
	return i
}

type buildState int

const (
	RAMPUP buildState = iota
	STEADY
	RAMPDOWN
)

func (b *SyntheticPcapTraceBuilder) Generate(pcapDatabaseDir string, pcapOut string) {
	b.pcapDB = NewPCAPDatabase(pcapDatabaseDir)
	f, err := os.Create(pcapOut)
	if err != nil {
		fmt.Printf("Error opening pcap output file %s : %s", pcapOut, err.Error())
		os.Exit(1)
	}
	defer f.Close()
	b.pcapOUT = pcapgo.NewWriter(f)
	b.pcapOUT.WriteFileHeader(65536, layers.LinkTypeEthernet)

	flowTable := make(map[int64]*Flow)
	state := RAMPUP
	var startSteadyAt time.Time
	run := true
	for run {

		if state == RAMPUP {
			// Generate flows for one second of traffic, up to max_flow
			if b.lastSecondFlows < b.maxFlowsPerSecond {
				for b.lastSecondFlows < b.maxFlowsPerSecond {
					pinfo := b.pcapDB.GetNext()
					f := b.newFlow(pinfo)
					flowTable[f.ID] = f
					b.lastSecondFlows += pinfo.Flows
				}
			}
		}
		if state == RAMPUP && lenFlowTable(&flowTable) >= b.maxFlows {
			state = STEADY
			startSteadyAt = b.currentPacketTime
		}
		if state == STEADY && b.currentPacketTime.Sub(startSteadyAt) >= (time.Duration(b.GoalSteadyStateSeconds)*time.Second) {
			state = RAMPDOWN
		}
		if state == RAMPDOWN {
			flowsRemoved := b.GoalFlowRampUpDownPerSecond
			for flowsRemoved > 0 && lenFlowTable(&flowTable) > 0 {
				flowsRemoved -= removeFlowTable(&flowTable, b.rand.Intn(len(flowTable)))
			}
			if lenFlowTable(&flowTable) == 0 {
				b.flushPackets()
				run = false
				break
			}
		}
		log.Printf("state %d generated %d flows %v : flowtable %d", state, b.lastSecondFlows, b.currentPacketTime.Sub(b.startTime), lenFlowTable(&flowTable))

		for _, f := range flowTable {
			b.processPackets(f)
			if b.genLimitPackets > 0 && b.generatedPackets >= b.genLimitPackets {
				run = false
				break
			}
			if b.genLimitSeconds > 0 && b.currentPacketTime.Sub(b.startTime) >= (time.Duration(b.genLimitSeconds)*time.Second) {
				run = false
				break
			}
			if b.genLimitMB > 0 && (b.generatedBytes/1024/1024) >= b.genLimitMB {
				run = false
				break
			}
		}
	}
}

func NewSyntheticPcapTraceBuilder(GoalMbps int, GoalAvgPacketSize int, GoalFlowRampUpDownPerSecond int, GoalFlowSteadyStatePerSecond int, GoalSteadyStateSeconds int) *SyntheticPcapTraceBuilder {
	b := &SyntheticPcapTraceBuilder{
		GoalMbps:                     GoalMbps,
		GoalAvgPacketSize:            GoalAvgPacketSize,
		GoalFlowRampUpDownPerSecond:  GoalFlowRampUpDownPerSecond,
		GoalFlowSteadyStatePerSecond: GoalFlowSteadyStatePerSecond,
		GoalSteadyStateSeconds:       GoalSteadyStateSeconds,
	}
	b.updateMaxValues()
	b.rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	b.startTime = time.Now()
	b.currentPacketTime = b.startTime
	return b
}

func main() {
	debug := false
	flag.BoolVar(&debug, "debug", false, "print debug messages")
	flag.Parse()

	logOutput, _ := os.Open(os.DevNull)
	if debug {
		logOutput = os.Stdout
	}
	log.SetOutput(logOutput)

	b := NewSyntheticPcapTraceBuilder(100, 1000, 1000, 10000, 120)
	b.genLimitSeconds = 1200
	b.Generate("template", "out.pcap")
}
