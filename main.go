package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "replay":
		err = runReplayCommand(os.Args[2:])
	case "dump":
		err = runDumpCommand(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		if os.Args[1] != "replay" && os.Args[1] != "dump" {
			fmt.Fprintln(os.Stderr)
			printUsage()
		}
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "pcap-stream replays syslog traffic from a pcap file\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  pcap-stream replay [flags]\n")
	fmt.Fprintf(os.Stderr, "  pcap-stream dump [flags]\n\n")
	fmt.Fprintf(os.Stderr, "Run 'pcap-stream <command> -h' for command flags.\n")
}

func printReplayUsage() {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  pcap-stream replay --pcap <path> --send-target <host:port> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	fs.String("pcap", "", "Path to .pcap file (required)")
	fs.String("send-target", "", "Replay destination host:port (required)")
	fs.String("send-proto", "tcp", "Replay destination protocol: tcp or udp")
	fs.Int("packet-dst-port", 0, "Packet destination TCP port filter (default: send-target port)")
	fs.String("packet-src-ip", "", "Packet source IP filter")
	fs.Bool("packet-exclude-loopback", true, "Exclude packet traffic with loopback src or dst")
	fs.Bool("dry-run", false, "Analyze and reconstruct streams without sending")

	fs.Usage()
}

func printDumpUsage() {
	fs := flag.NewFlagSet("dump", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  pcap-stream dump --pcap <path> --out-file <path> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	fs.String("pcap", "", "Path to .pcap file (required)")
	fs.String("out-file", "", "Path to output log file (required)")
	fs.Int("packet-dst-port", 0, "Packet destination TCP port filter (optional)")
	fs.String("packet-src-ip", "", "Packet source IP filter")
	fs.Bool("packet-exclude-loopback", true, "Exclude packet traffic with loopback src or dst")

	fs.Usage()
}
