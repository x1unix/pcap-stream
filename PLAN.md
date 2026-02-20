# PLAN: pcap-stream syslog replay tool

## Goal
Build a standalone CLI in `pcap-stream` that replays syslog traffic from a `.pcap` into an Alloy `loki.source.syslog` listener, with explicit separation between packet-filter flags and replay-send flags.

## Input capture context
- Primary sample: `../escalations/syslog/capture.pcap`
- Traffic observed: TCP only
- Syslog framing observed: RFC6587 octet-counting (`<length> <syslog message>`)
- Capture includes both remote ingress and loopback forwarded traffic; replay should support filtering to avoid duplicates.

## CLI design

### Command
- `pcap-stream replay`

### Required flags
- `--pcap <path>`
- `--send-target <host:port>`

### Packet-filter flags (explicit `packet-` prefix)
- `--packet-dst-port <port>`
  - Optional
  - Defaults to the port parsed from `--send-target`
- `--packet-src-ip <ip>`
  - Optional
- `--packet-exclude-loopback`
  - Optional, default: `true`
  - Excludes `127.0.0.0/8` source or destination packets

### Other behavior flags
- `--dry-run` (analyze only, do not send)
- (optional follow-up) `--verbose` for detailed stream/filter diagnostics

## Replay behavior
1. Read pcap with `gopacket/pcapgo`.
2. Decode packet layers.
3. Keep only TCP payload packets matching packet filters.
4. Group payload by TCP flow direction (`srcIP:srcPort -> dstIP:dstPort`) for client-to-server streams.
5. Reassemble byte stream per flow in sequence order.
6. Open TCP connection(s) to `--send-target`.
7. Write reassembled payload bytes to target.
8. Print replay summary:
   - packets seen
   - packets matched filters
   - streams reconstructed
   - bytes replayed
   - skipped packets/reasons

## Duplicate safety
- Default behavior should skip loopback traffic (`--packet-exclude-loopback=true`).
- Users can explicitly constrain sender with `--packet-src-ip 100.64.255.36`.

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

## Example usage

```bash
pcap-stream replay \
  --pcap ../escalations/syslog/capture.pcap \
  --send-target 127.0.0.1:51898 \
  --packet-src-ip 100.64.255.36 \
  --packet-exclude-loopback \
  --dry-run
```

```bash
pcap-stream replay \
  --pcap ../escalations/syslog/capture.pcap \
  --send-target 127.0.0.1:51898 \
  --packet-src-ip 100.64.255.36 \
  --packet-exclude-loopback
```

## Implementation steps
1. Add dependencies in `pcap-stream/go.mod`:
   - `github.com/google/gopacket`
2. Implement CLI entrypoint and flag parsing.
3. Implement packet decode/filter pipeline.
4. Implement TCP flow reassembly and replay.
5. Implement dry-run and summary reporting.
6. Test with `capture.pcap`.
7. Document known limitations and usage notes in `README.md` (follow-up).

## Known limitations (initial version)
- TCP-only replay (no UDP replay initially).
- No exact original timing replay in v1 (best-effort stream replay only).
- If pcap has packet loss or out-of-order gaps, replay may be incomplete for affected streams.
