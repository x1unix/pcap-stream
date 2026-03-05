# pcap-stream

CLI tool for replaying or dumping syslog traffic from a `.pcap` file.

Supports RFC6587 octet-counting and newline-delimited framing. TCP and UDP replay. Linux SLL2, Ethernet, IPv4, IPv6.

> **Note:** pcapng is not supported. Convert first: `tshark -r capture.pcapng -F pcap -w capture.pcap`

## Commands

```
pcap-stream replay --pcap <path> --send-target <host:port> [flags]
pcap-stream dump   --pcap <path> --out-file <path> [flags]
```

---

## replay

Reassembles TCP flows from a pcap and sends them to a target host.

### Flags

| Flag | Default | Description |
|---|---|---|
| `--pcap` | — | Path to `.pcap` file (required) |
| `--send-target` | — | Destination `host:port` (required) |
| `--send-proto` | `tcp` | Send protocol: `tcp` or `udp` |
| `--packet-dst-port` | send-target port | Packet destination port filter |
| `--packet-exclude-loopback` | `true` | Exclude packets with loopback src or dst |
| `--dry-run` | `false` | Reconstruct streams without sending |

For TCP, each reassembled flow is written as a single connection.
For UDP, syslog messages are extracted from each flow and sent as individual datagrams.

### Examples

Dry run — analyze without sending:
```bash
pcap-stream replay \
  --pcap capture.pcap \
  --send-target 127.0.0.1:51898 \
  --dry-run
```

Replay over TCP, filtering to port 514:
```bash
pcap-stream replay \
  --pcap capture.pcap \
  --send-target 127.0.0.1:51898 \
  --packet-dst-port 514
```

Replay over UDP (extracts individual syslog messages):
```bash
pcap-stream replay \
  --pcap capture.pcap \
  --send-target 127.0.0.1:51898 \
  --send-proto udp \
  --packet-dst-port 514
```

Include loopback traffic:
```bash
pcap-stream replay \
  --pcap capture.pcap \
  --send-target 127.0.0.1:51898 \
  --packet-exclude-loopback=false
```

---

## dump

Reassembles TCP flows from a pcap and writes them to a file.

### Flags

| Flag | Default | Description |
|---|---|---|
| `--pcap` | — | Path to `.pcap` file (required) |
| `--out-file` | — | Path to output file (required) |
| `--packet-dst-port` | — | Packet destination port filter (required) |
| `--packet-exclude-loopback` | `true` | Exclude packets with loopback src or dst |
| `--split-messages` | `false` | Split output by framing type |

Without `--split-messages`, raw reassembled stream bytes are written concatenated.

With `--split-messages`, framing is detected per flow:
- **RFC6587 octet-counting** (`<count> <message>`): each message is written as `<count> <message>\n`, preserving the original prefix.
- **Newline-delimited**: each line is written on its own line.

### Examples

Raw dump of reassembled streams:
```bash
pcap-stream dump \
  --pcap capture.pcap \
  --out-file output.log \
  --packet-dst-port 514
```

Dump with message splitting (framing-aware):
```bash
pcap-stream dump \
  --pcap capture.pcap \
  --out-file output.log \
  --packet-dst-port 514 \
  --split-messages
```

---

## Summary output

Both commands print a summary to stdout after completion. Example for `replay`:

```
mode: replay
pcap: capture.pcap
send target: 127.0.0.1:51898
send proto: tcp
...

packets seen: 4821
packets matched: 1204
streams detected: 3
streams reconstructed: 3
streams replayed: 3
bytes replayed: 1048576
```
