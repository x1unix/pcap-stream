# PLAN: pcap-stream syslog replay tool

## Goal
Build a standalone CLI in `pcap-stream` that replays syslog traffic from a `.pcap` into an Alloy `loki.source.syslog` listener, with explicit separation between packet-filter flags and replay-send flags.

## Input capture context
- Primary sample: `../escalations/syslog/capture.pcap`
- Traffic observed: TCP only
- Syslog framing observed: RFC6587 octet-counting (`<length> <syslog message>`)
- Capture includes both remote ingress and loopback forwarded traffic; replay should support filtering to avoid duplicates.

## CLI design

### Commands
- `pcap-stream replay` — reassemble and send traffic to a target
- `pcap-stream dump` — reassemble and write traffic to a file

### replay flags
- `--pcap <path>` (required)
- `--send-target <host:port>` (required)
- `--send-proto <tcp|udp>` — default: `tcp`
- `--packet-dst-port <port>` — optional, defaults to port from `--send-target`
- `--packet-exclude-loopback` — default: `true`
- `--dry-run` — analyze and reconstruct without sending

### dump flags
- `--pcap <path>` (required)
- `--out-file <path>` (required)
- `--packet-dst-port <port>` (required)
- `--packet-exclude-loopback` — default: `true`
- `--split-messages` — split output by framing type instead of writing raw streams

## Replay behavior
1. Read pcap with `gopacket/pcapgo`.
2. Decode packet layers (Ethernet, Linux SLL2, IPv4, IPv6, TCP).
3. Keep only TCP payload packets matching packet filters.
4. Group payload by TCP flow (`srcIP:srcPort -> dstIP:dstPort`).
5. Reassemble byte stream per flow in sequence order (gap and duplicate tracking).
6. For TCP: write each reassembled stream to the target as a single connection.
7. For UDP: extract individual syslog messages via framing detection and send as datagrams.
8. Print replay summary.

## Dump behavior
1. Reassemble flows identically to replay.
2. Without `--split-messages`: write all reassembled stream bytes concatenated into the output file.
3. With `--split-messages`: detect framing per flow.
   - RFC6587 octet-counting detected: write each message as `<count> <message>\n`, preserving the original prefix.
   - Non-transparent (newline-delimited): split on `\n` and write each message on its own line.

## Syslog framing detection
`extractSyslogMessages` tries in order:
1. RFC6587 octet-counting: leading decimal count followed by space.
2. Newline-delimited: split on `\n`.
3. Fallback: treat entire payload as single message.

Dump's `--split-messages` uses the same detection order but handles RFC6587 separately to preserve the octet-count prefix in output.

## Duplicate safety
- Default behavior skips loopback traffic (`--packet-exclude-loopback=true`).
- Use `--packet-dst-port` to restrict to the relevant service port.

## Validation plan

### Dry-run validation
- Run against sample pcap and confirm:
  - non-zero matched packet count
  - reasonable stream count
  - no fatal parse errors

### Live replay validation
- Replay to Alloy listener using `--send-target 127.0.0.1:51898`.
- Verify ingestion in Alloy/Loki:
  - increase in `loki_source_syslog_entries_total`
  - expected `loki_source_syslog_parsing_errors_total` behavior
  - logs visible downstream (e.g., `loki.echo` or Loki query)

## Implementation status
- [x] Add `github.com/google/gopacket` dependency
- [x] CLI entrypoint and flag parsing (`replay`, `dump`)
- [x] Packet decode/filter pipeline (Ethernet, Linux SLL2, IPv4/IPv6, TCP)
- [x] TCP flow reassembly with gap and duplicate detection
- [x] TCP replay
- [x] UDP replay with syslog message extraction
- [x] Dry-run mode and summary reporting
- [x] `dump` command with raw stream output
- [x] `--split-messages` with framing-aware output (preserves RFC6587 prefix)
- [ ] README documentation

## Known limitations
- No exact original timing replay (best-effort stream replay).
- If pcap has packet loss or out-of-order gaps, replay may be incomplete for affected streams.
- pcapng format not supported; convert to pcap first (`tshark -F pcap`).
- No deduplication of log messages.
