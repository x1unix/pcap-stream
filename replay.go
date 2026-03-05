package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type packetFilterConfig struct {
	packetDstPort         int
	packetExcludeLoopback bool
}

type replayConfig struct {
	pcapPath   string
	sendTarget string
	sendProto  string
	dryRun     bool
	filter     packetFilterConfig
}

type dumpConfig struct {
	pcapPath      string
	outFile       string
	splitMessages bool
	filter        packetFilterConfig
}

type replayStats struct {
	packetsSeen          int64
	packetsMatched       int64
	streamsDetected      int64
	streamsReconstructed int64
	streamsReplayed      int64
	streamsFailed        int64
	bytesReassembled     int64
	bytesReplayed        int64
	bytesDumped          int64
	messagesExtracted    int64
	messagesSent         int64
	reassemblyGaps       int64
	duplicateSegments    int64
	pcapLinkType         uint32
	decoderLinkType      string
	firstSendError       string
	skipped              map[string]int64
}

type decodedTCPPacket struct {
	srcIP net.IP
	dstIP net.IP
	tcp   *layers.TCP
}

type flowKey struct {
	srcIP   string
	srcPort uint16
	dstIP   string
	dstPort uint16
}

func (k flowKey) String() string {
	return fmt.Sprintf("%s:%d->%s:%d", k.srcIP, k.srcPort, k.dstIP, k.dstPort)
}

type flowSegments struct {
	firstTimestamp time.Time
	segments       []tcpSegment
}

type reassembledFlow struct {
	key            flowKey
	firstTimestamp time.Time
	payload        []byte
}

type tcpSegment struct {
	seq       uint32
	payload   []byte
	timestamp time.Time
}

const (
	linuxSLL2LinkType     uint32 = 276
	linuxSLL2HeaderLength        = 20
)

func runReplayCommand(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	pcapPath := fs.String("pcap", "", "")
	sendTarget := fs.String("send-target", "", "")
	sendProto := fs.String("send-proto", "tcp", "")
	packetDstPort := fs.Int("packet-dst-port", 0, "")
	packetExcludeLoopback := fs.Bool("packet-exclude-loopback", true, "")
	dryRun := fs.Bool("dry-run", false, "")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printReplayUsage()
			return nil
		}
		return err
	}

	if *pcapPath == "" {
		return errors.New("--pcap is required")
	}
	if *sendTarget == "" {
		return errors.New("--send-target is required")
	}

	normalizedProto, err := normalizeSendProto(*sendProto)
	if err != nil {
		return err
	}

	sendPort, err := parseTargetPort(*sendTarget)
	if err != nil {
		return fmt.Errorf("invalid --send-target: %w", err)
	}

	resolvedDstPort := *packetDstPort
	if resolvedDstPort == 0 {
		resolvedDstPort = sendPort
	}
	if resolvedDstPort < 1 || resolvedDstPort > 65535 {
		return fmt.Errorf("--packet-dst-port out of range: %d", resolvedDstPort)
	}

	cfg := replayConfig{
		pcapPath:   *pcapPath,
		sendTarget: *sendTarget,
		sendProto:  normalizedProto,
		dryRun:     *dryRun,
		filter: packetFilterConfig{
			packetDstPort:         resolvedDstPort,
			packetExcludeLoopback: *packetExcludeLoopback,
		},
	}

	stats, replayErr := replayFromPCAP(cfg)
	printReplaySummary(cfg, stats)

	if replayErr != nil {
		return replayErr
	}

	if stats.streamsFailed > 0 {
		return fmt.Errorf("%d stream(s) failed during replay", stats.streamsFailed)
	}

	return nil
}

func runDumpCommand(args []string) error {
	fs := flag.NewFlagSet("dump", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	pcapPath := fs.String("pcap", "", "")
	outFile := fs.String("out-file", "", "")
	splitMessages := fs.Bool("split-messages", false, "")
	packetDstPort := fs.Int("packet-dst-port", 0, "")
	packetExcludeLoopback := fs.Bool("packet-exclude-loopback", true, "")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printDumpUsage()
			return nil
		}
		return err
	}

	if *pcapPath == "" {
		return errors.New("--pcap is required")
	}
	if *outFile == "" {
		return errors.New("--out-file is required")
	}
	if *packetDstPort == 0 {
		return errors.New("--packet-dst-port is required")
	}

	if *packetDstPort < 1 || *packetDstPort > 65535 {
		return fmt.Errorf("--packet-dst-port out of range: %d", *packetDstPort)
	}

	cfg := dumpConfig{
		pcapPath:      *pcapPath,
		outFile:       *outFile,
		splitMessages: *splitMessages,
		filter: packetFilterConfig{
			packetDstPort:         *packetDstPort,
			packetExcludeLoopback: *packetExcludeLoopback,
		},
	}

	stats, dumpErr := dumpFromPCAP(cfg)
	printDumpSummary(cfg, stats)

	if dumpErr != nil {
		return dumpErr
	}

	return nil
}

func normalizeSendProto(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "tcp", "udp":
		return value, nil
	default:
		return "", fmt.Errorf("invalid --send-proto %q (expected tcp or udp)", raw)
	}
}

func parseTargetPort(target string) (int, error) {
	_, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return 0, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, err
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port out of range: %d", port)
	}

	return port, nil
}

func replayFromPCAP(cfg replayConfig) (replayStats, error) {
	flows, stats, err := collectReassembledFlows(cfg.pcapPath, cfg.filter)
	if err != nil {
		return stats, err
	}

	if cfg.dryRun {
		stats.bytesReplayed = stats.bytesReassembled
		return stats, nil
	}

	for i := range flows {
		payload := flows[i].payload

		if cfg.sendProto == "tcp" {
			written, sendErr := writeTCPStream(cfg.sendTarget, payload)
			if sendErr != nil {
				stats.streamsFailed++
				stats.skipped["send_error"]++
				if stats.firstSendError == "" {
					stats.firstSendError = sendErr.Error()
				}
				continue
			}

			stats.streamsReplayed++
			stats.bytesReplayed += int64(written)
			continue
		}

		datagrams := extractSyslogMessages(payload)
		stats.messagesExtracted += int64(len(datagrams))

		written, sent, sendErr := writeUDPDatagrams(cfg.sendTarget, datagrams)
		stats.messagesSent += int64(sent)
		if sendErr != nil {
			stats.streamsFailed++
			stats.skipped["send_error"]++
			stats.bytesReplayed += int64(written)
			if stats.firstSendError == "" {
				stats.firstSendError = sendErr.Error()
			}
			continue
		}

		stats.streamsReplayed++
		stats.bytesReplayed += int64(written)
	}

	return stats, nil
}

func dumpFromPCAP(cfg dumpConfig) (replayStats, error) {
	flows, stats, err := collectReassembledFlows(cfg.pcapPath, cfg.filter)
	if err != nil {
		return stats, err
	}

	outFile, err := os.Create(cfg.outFile)
	if err != nil {
		return stats, fmt.Errorf("create output file: %w", err)
	}
	defer outFile.Close()

	writer := bufio.NewWriter(outFile)

	for i := range flows {
		payload := flows[i].payload
		if len(payload) == 0 {
			continue
		}

		if !cfg.splitMessages {
			n, writeErr := writer.Write(payload)
			stats.bytesDumped += int64(n)
			if writeErr != nil {
				return stats, fmt.Errorf("write output file: %w", writeErr)
			}
			continue
		}

		messages, octetCounting := parseRFC6587OctetCounting(payload)
		if !octetCounting {
			messages = splitNewlineMessages(payload)
		}

		for j := range messages {
			message := messages[j]
			if len(message) == 0 {
				continue
			}

			if octetCounting {
				hn, writeErr := writer.WriteString(strconv.Itoa(len(message)) + " ")
				stats.bytesDumped += int64(hn)
				if writeErr != nil {
					return stats, fmt.Errorf("write output file: %w", writeErr)
				}
			}

			n, writeErr := writer.Write(message)
			stats.bytesDumped += int64(n)
			if writeErr != nil {
				return stats, fmt.Errorf("write output file: %w", writeErr)
			}

			if err := writer.WriteByte('\n'); err != nil {
				return stats, fmt.Errorf("write output file: %w", err)
			}
			stats.bytesDumped++
		}
	}

	if err := writer.Flush(); err != nil {
		return stats, fmt.Errorf("flush output file: %w", err)
	}

	return stats, nil
}

func collectReassembledFlows(pcapPath string, filter packetFilterConfig) ([]reassembledFlow, replayStats, error) {
	stats := replayStats{skipped: make(map[string]int64)}

	f, err := os.Open(pcapPath)
	if err != nil {
		return nil, stats, fmt.Errorf("open pcap: %w", err)
	}
	defer f.Close()

	rawLinkType, err := readPCAPLinkType(f)
	if err != nil {
		return nil, stats, fmt.Errorf("read pcap header: %w", err)
	}
	stats.pcapLinkType = rawLinkType

	r, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, stats, fmt.Errorf("create pcap reader: %w", err)
	}

	linkType := r.LinkType()
	stats.decoderLinkType = linkType.String()
	flows := make(map[flowKey]*flowSegments)

	for {
		data, ci, readErr := r.ReadPacketData()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			stats.skipped["pcap_read_error"]++
			continue
		}

		stats.packetsSeen++

		decoded, reason := decodeTCPPacket(data, linkType, rawLinkType)
		if reason != "" {
			stats.skipped[reason]++
			continue
		}

		srcIP := decoded.srcIP
		dstIP := decoded.dstIP
		tcp := decoded.tcp

		if len(tcp.Payload) == 0 {
			stats.skipped["empty_payload"]++
			continue
		}

		if filter.packetExcludeLoopback && (srcIP.IsLoopback() || dstIP.IsLoopback()) {
			stats.skipped["loopback_excluded"]++
			continue
		}

		if filter.packetDstPort > 0 && int(tcp.DstPort) != filter.packetDstPort {
			stats.skipped["dst_port_mismatch"]++
			continue
		}

		stats.packetsMatched++

		key := flowKey{
			srcIP:   srcIP.String(),
			srcPort: uint16(tcp.SrcPort),
			dstIP:   dstIP.String(),
			dstPort: uint16(tcp.DstPort),
		}

		flow := flows[key]
		if flow == nil {
			flow = &flowSegments{firstTimestamp: ci.Timestamp}
			flows[key] = flow
		}

		payloadCopy := append([]byte(nil), tcp.Payload...)
		flow.segments = append(flow.segments, tcpSegment{
			seq:       tcp.Seq,
			payload:   payloadCopy,
			timestamp: ci.Timestamp,
		})
	}

	stats.streamsDetected = int64(len(flows))

	reassembled := make([]reassembledFlow, 0, len(flows))
	for key, flow := range flows {
		payload, gaps, duplicates := reassembleTCPStream(flow.segments)
		stats.reassemblyGaps += int64(gaps)
		stats.duplicateSegments += int64(duplicates)
		if len(payload) == 0 {
			continue
		}

		reassembled = append(reassembled, reassembledFlow{
			key:            key,
			firstTimestamp: flow.firstTimestamp,
			payload:        payload,
		})

		stats.streamsReconstructed++
		stats.bytesReassembled += int64(len(payload))
	}

	sort.Slice(reassembled, func(i, j int) bool {
		if reassembled[i].firstTimestamp.Equal(reassembled[j].firstTimestamp) {
			return reassembled[i].key.String() < reassembled[j].key.String()
		}
		return reassembled[i].firstTimestamp.Before(reassembled[j].firstTimestamp)
	})

	return reassembled, stats, nil
}

func readPCAPLinkType(file *os.File) (uint32, error) {
	var header [24]byte
	if _, err := file.ReadAt(header[:], 0); err != nil {
		return 0, err
	}

	magic := [4]byte{header[0], header[1], header[2], header[3]}
	var byteOrder binary.ByteOrder

	switch magic {
	case [4]byte{0xa1, 0xb2, 0xc3, 0xd4}, [4]byte{0xa1, 0xb2, 0x3c, 0x4d}:
		byteOrder = binary.BigEndian
	case [4]byte{0xd4, 0xc3, 0xb2, 0xa1}, [4]byte{0x4d, 0x3c, 0xb2, 0xa1}:
		byteOrder = binary.LittleEndian
	case [4]byte{0x0a, 0x0d, 0x0d, 0x0a}:
		return 0, errors.New("pcapng is not supported; convert to pcap first")
	default:
		return 0, fmt.Errorf("unsupported pcap magic: %x", magic)
	}

	return byteOrder.Uint32(header[20:24]), nil
}

func decodeTCPPacket(data []byte, linkType layers.LinkType, rawLinkType uint32) (decodedTCPPacket, string) {
	if rawLinkType == linuxSLL2LinkType {
		return decodeLinuxSLL2TCPPacket(data)
	}

	packet := gopacket.NewPacket(data, linkType, gopacket.NoCopy)
	if packet.ErrorLayer() != nil {
		return decodedTCPPacket{}, "decode_error"
	}

	srcIP, dstIP, ok := packetIPs(packet)
	if !ok {
		return decodedTCPPacket{}, "non_ip"
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return decodedTCPPacket{}, "non_tcp"
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return decodedTCPPacket{}, "decode_error"
	}

	return decodedTCPPacket{srcIP: srcIP, dstIP: dstIP, tcp: tcp}, ""
}

func decodeLinuxSLL2TCPPacket(data []byte) (decodedTCPPacket, string) {
	if len(data) < linuxSLL2HeaderLength {
		return decodedTCPPacket{}, "decode_error"
	}

	proto := binary.BigEndian.Uint16(data[0:2])
	networkPayload := data[linuxSLL2HeaderLength:]

	var packet gopacket.Packet
	switch layers.EthernetType(proto) {
	case layers.EthernetTypeIPv4:
		packet = gopacket.NewPacket(networkPayload, layers.LayerTypeIPv4, gopacket.NoCopy)
	case layers.EthernetTypeIPv6:
		packet = gopacket.NewPacket(networkPayload, layers.LayerTypeIPv6, gopacket.NoCopy)
	default:
		return decodedTCPPacket{}, "non_ip"
	}

	if packet.ErrorLayer() != nil {
		return decodedTCPPacket{}, "decode_error"
	}

	srcIP, dstIP, ok := packetIPs(packet)
	if !ok {
		return decodedTCPPacket{}, "non_ip"
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return decodedTCPPacket{}, "non_tcp"
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return decodedTCPPacket{}, "decode_error"
	}

	return decodedTCPPacket{srcIP: srcIP, dstIP: dstIP, tcp: tcp}, ""
}

func packetIPs(packet gopacket.Packet) (net.IP, net.IP, bool) {
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		return ipv4.SrcIP, ipv4.DstIP, true
	}

	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)
		return ipv6.SrcIP, ipv6.DstIP, true
	}

	return nil, nil, false
}

func reassembleTCPStream(segments []tcpSegment) ([]byte, int, int) {
	if len(segments) == 0 {
		return nil, 0, 0
	}

	sort.Slice(segments, func(i, j int) bool {
		if segments[i].seq == segments[j].seq {
			return segments[i].timestamp.Before(segments[j].timestamp)
		}
		return segments[i].seq < segments[j].seq
	})

	capacity := 0
	for i := range segments {
		capacity += len(segments[i].payload)
	}

	out := make([]byte, 0, capacity)
	expectedSeq := segments[0].seq
	gaps := 0
	duplicates := 0

	for i := range segments {
		seg := segments[i]
		if len(seg.payload) == 0 {
			continue
		}

		endSeq := seg.seq + uint32(len(seg.payload))

		if seg.seq > expectedSeq {
			gaps++
		}

		if endSeq <= expectedSeq {
			duplicates++
			continue
		}

		startOffset := 0
		if seg.seq < expectedSeq {
			startOffset = int(expectedSeq - seg.seq)
		}

		out = append(out, seg.payload[startOffset:]...)
		expectedSeq = endSeq
	}

	return out, gaps, duplicates
}

func writeTCPStream(target string, payload []byte) (int, error) {
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return 0, err
	}

	total := 0
	for total < len(payload) {
		n, writeErr := conn.Write(payload[total:])
		total += n
		if writeErr != nil {
			return total, writeErr
		}
	}

	return total, nil
}

func writeUDPDatagrams(target string, datagrams [][]byte) (int, int, error) {
	conn, err := net.DialTimeout("udp", target, 5*time.Second)
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return 0, 0, err
	}

	bytesWritten := 0
	sent := 0

	for i := range datagrams {
		datagram := datagrams[i]
		if len(datagram) == 0 {
			continue
		}

		n, writeErr := conn.Write(datagram)
		bytesWritten += n
		if writeErr != nil {
			return bytesWritten, sent, writeErr
		}

		sent++
	}

	return bytesWritten, sent, nil
}

func extractSyslogMessages(payload []byte) [][]byte {
	if messages, ok := parseRFC6587OctetCounting(payload); ok {
		return messages
	}

	if messages := splitNewlineMessages(payload); len(messages) > 0 {
		return messages
	}

	if len(payload) == 0 {
		return nil
	}

	message := append([]byte(nil), payload...)
	return [][]byte{message}
}

func parseRFC6587OctetCounting(payload []byte) ([][]byte, bool) {
	if len(payload) == 0 {
		return nil, false
	}

	idx := 0
	messages := make([][]byte, 0)

	for idx < len(payload) {
		for idx < len(payload) && (payload[idx] == '\n' || payload[idx] == '\r') {
			idx++
		}
		if idx >= len(payload) {
			break
		}

		lenStart := idx
		for idx < len(payload) && payload[idx] >= '0' && payload[idx] <= '9' {
			idx++
		}
		if idx == lenStart || idx >= len(payload) || payload[idx] != ' ' {
			return nil, false
		}

		length, err := strconv.Atoi(string(payload[lenStart:idx]))
		if err != nil || length < 0 {
			return nil, false
		}

		idx++
		if idx+length > len(payload) {
			return nil, false
		}

		message := append([]byte(nil), payload[idx:idx+length]...)
		messages = append(messages, message)
		idx += length
	}

	if len(messages) == 0 {
		return nil, false
	}

	return messages, true
}

func splitNewlineMessages(payload []byte) [][]byte {
	parts := bytes.Split(payload, []byte{'\n'})
	out := make([][]byte, 0, len(parts))

	for i := range parts {
		line := bytes.TrimSuffix(parts[i], []byte{'\r'})
		if len(line) == 0 {
			continue
		}
		out = append(out, append([]byte(nil), line...))
	}

	return out
}

func printReplaySummary(cfg replayConfig, stats replayStats) {
	mode := "replay"
	if cfg.dryRun {
		mode = "dry-run"
	}

	fmt.Printf("mode: %s\n", mode)
	fmt.Printf("pcap: %s\n", cfg.pcapPath)
	fmt.Printf("pcap link type: %d\n", stats.pcapLinkType)
	fmt.Printf("gopacket link type: %s\n", stats.decoderLinkType)
	fmt.Printf("send target: %s\n", cfg.sendTarget)
	fmt.Printf("send proto: %s\n", cfg.sendProto)
	fmt.Printf("packet dst port filter: %d\n", cfg.filter.packetDstPort)
	fmt.Printf("packet exclude loopback: %t\n", cfg.filter.packetExcludeLoopback)
	fmt.Println()

	fmt.Printf("packets seen: %d\n", stats.packetsSeen)
	fmt.Printf("packets matched: %d\n", stats.packetsMatched)
	fmt.Printf("streams detected: %d\n", stats.streamsDetected)
	fmt.Printf("streams reconstructed: %d\n", stats.streamsReconstructed)
	fmt.Printf("reassembly gaps: %d\n", stats.reassemblyGaps)
	fmt.Printf("duplicate segments skipped: %d\n", stats.duplicateSegments)
	fmt.Printf("bytes reassembled: %d\n", stats.bytesReassembled)

	if cfg.dryRun {
		fmt.Printf("bytes replayable: %d\n", stats.bytesReplayed)
	} else {
		fmt.Printf("streams replayed: %d\n", stats.streamsReplayed)
		fmt.Printf("streams failed: %d\n", stats.streamsFailed)
		fmt.Printf("bytes replayed: %d\n", stats.bytesReplayed)
		if cfg.sendProto == "udp" {
			fmt.Printf("messages extracted: %d\n", stats.messagesExtracted)
			fmt.Printf("messages sent: %d\n", stats.messagesSent)
		}
		if stats.firstSendError != "" {
			fmt.Printf("first send error: %s\n", stats.firstSendError)
		}
	}

	if len(stats.skipped) > 0 {
		fmt.Println("skipped packets/reasons:")
		reasons := make([]string, 0, len(stats.skipped))
		for reason := range stats.skipped {
			reasons = append(reasons, reason)
		}
		sort.Strings(reasons)
		for _, reason := range reasons {
			fmt.Printf("  %s: %d\n", reason, stats.skipped[reason])
		}
	}
}

func printDumpSummary(cfg dumpConfig, stats replayStats) {
	fmt.Printf("mode: dump\n")
	fmt.Printf("pcap: %s\n", cfg.pcapPath)
	fmt.Printf("pcap link type: %d\n", stats.pcapLinkType)
	fmt.Printf("gopacket link type: %s\n", stats.decoderLinkType)
	fmt.Printf("out file: %s\n", cfg.outFile)
	fmt.Printf("packet dst port filter: %d\n", cfg.filter.packetDstPort)
	fmt.Printf("packet exclude loopback: %t\n", cfg.filter.packetExcludeLoopback)
	fmt.Println()

	fmt.Printf("packets seen: %d\n", stats.packetsSeen)
	fmt.Printf("packets matched: %d\n", stats.packetsMatched)
	fmt.Printf("streams detected: %d\n", stats.streamsDetected)
	fmt.Printf("streams reconstructed: %d\n", stats.streamsReconstructed)
	fmt.Printf("bytes dumped: %d\n", stats.bytesDumped)

	if len(stats.skipped) > 0 {
		fmt.Println("skipped packets/reasons:")
		reasons := make([]string, 0, len(stats.skipped))
		for reason := range stats.skipped {
			reasons = append(reasons, reason)
		}
		sort.Strings(reasons)
		for _, reason := range reasons {
			fmt.Printf("  %s: %d\n", reason, stats.skipped[reason])
		}
	}
}
