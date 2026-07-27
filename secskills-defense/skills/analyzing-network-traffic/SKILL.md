---
name: analyzing-network-traffic
description: Analyze packet captures and network telemetry for intrusion evidence — capture and handling, the Wireshark/tshark triage funnel, Zeek log mining, Suricata rule runs, beacon and DNS-tunnel detection, TLS/JA3 fingerprinting, HTTP and file carving, exfiltration hunting, and IOC handoff. Use when a `.pcap` or `.pcapng` capture lands on your desk, when a suspected C2 beacon needs confirming, when there is data exfiltration to investigate, when malware network behaviour must be characterized from what it emitted, when a Zeek or Suricata alert needs running down, or when DNS tunneling or unusual TLS is suspected.
verified: 2026-07-26
---

# Analyzing Network Traffic

Packet capture is ground truth the endpoint can lie about but the wire cannot:
every connection, DNS lookup, and byte transferred is recorded, whether or not
the host's logs survived. The analysis is turning a flat capture into a story —
who talked to whom, over what protocol, whether the pattern was human or
automated, and what left the network. You are reconstructing intent from
frames, not reading a verdict off a tool.

## When to Use

- A `.pcap` / `.pcapng` capture needs forensic review for intrusion evidence
- A suspected C2 beacon must be confirmed and its interval, jitter, and channel characterized
- Data exfiltration is suspected and you need to size it, time it, and name the destination
- Malware network behaviour must be documented from the traffic it actually emitted
- A Zeek `notice.log` or Suricata `eve.json` alert needs to be run down to a verdict
- DNS tunneling, a DGA, or anomalous TLS (odd certs, rare JA3, SNI mismatch) is suspected

## When NOT to Use

- **Proactively sweeping endpoint, network, cloud, and identity telemetry for
  undetected compromise** — use `hunting-threats`; this skill dissects one
  capture, a hunt spans data sources
- **Running the wider incident** — use `responding-to-incidents`; traffic
  analysis is one evidence stream feeding that process
- **Detonating a sample to *produce* the traffic** — use `analyzing-malware`;
  come here to analyze the pcap it emitted, not to run the binary
- **The evidence is cloud control-plane activity, not packets** (CloudTrail,
  VPC flow gaps, API calls) — use `investigating-aws-incidents`
- **Actively testing a live application** rather than analyzing a capture of
  it — use `testing-web-applications`

## Capture and Handling

Get the capture right or every later step inherits the gap. A truncated snaplen
or a dropped-packet capture cannot be fixed after the fact.

```bash
# Full-frame capture, no name resolution, write to disk (never parse live)
tcpdump -i eth0 -nn -s 0 -w case.pcap
# -s 0 takes full frames; a default snaplen truncates payloads and breaks carving

# Ring buffer for long-running capture: 20 files of 200 MB, oldest recycled
tcpdump -i eth0 -nn -s 0 -w case-%Y%m%d-%H%M%S.pcap -G 3600 -C 200 -W 20

# Capture without dropping under load: raise the kernel buffer, filter tightly
tcpdump -i eth0 -nn -s 0 -B 4096 'not port 22' -w case.pcap
# Confirm drops after: the summary line reports "packets dropped by kernel"
```

Check whether the capture is intact and what you are holding:

```bash
capinfos case.pcap        # packet count, duration, drop stats, snaplen, file type
tshark -r case.pcap -q -z io,phs   # protocol hierarchy — is the snaplen truncating?
```

- **pcapng vs pcap**: pcapng carries per-packet interface, comments, and name
  records; classic `.pcap` is a flat single-link format. `editcap -F libpcap
  in.pcapng out.pcap` downgrades for a tool that only reads pcap.
- **Split a huge file** so tools and memory cope:
  `editcap -c 1000000 big.pcap chunk.pcap` (per packet count) or
  `editcap -i 600 big.pcap chunk.pcap` (per 600 seconds).
- **Merge** related captures onto one timeline: `mergecap -w all.pcap a.pcap
  b.pcap` (sorts by timestamp).
- **Trim to a window** before shipping: `editcap -A "2026-07-26 00:00:00" -B
  "2026-07-26 06:00:00" case.pcap window.pcap`.
- **Anonymize** before sharing externally: `tcprewrite`/`bittwiste` to rewrite
  addresses, or `editcap -s <snaplen>` to truncate each packet to the first
  `snaplen` bytes (keeping headers, dropping trailing payload); TraceWrangler
  for deeper header/payload sanitization. Record what you changed so the
  recipient does not chase your rewrite as an artifact.

Hash the original and work on copies. `sha256sum case.pcap` goes in the case
notes; the evidence file is read-only from here on.

## The Triage Funnel

Start wide, narrow to the flows that matter. In Wireshark, work top-down:

- **Statistics > Protocol Hierarchy** — what protocols exist and in what
  proportion. Cleartext where you expected TLS, or a sliver of DNS carrying
  most of the bytes, is the first tell.
- **Statistics > Conversations** — sort by bytes and by duration. The longest
  and the largest flows are your first two leads (beacon vs bulk transfer).
- **Statistics > Endpoints** — which hosts talk to the most peers; map internal
  vs external at a glance.
- **Follow > TCP/HTTP/TLS Stream** — reassemble one conversation to read it as
  the application saw it.

Everything Wireshark does interactively, `tshark` does scriptably — which is how
you extract fields across a whole capture instead of clicking:

```bash
# Top talkers by bytes
tshark -r case.pcap -q -z conv,tcp

# Extract just the fields you want, tab-separated, for further processing
tshark -r case.pcap -T fields -E separator=/t \
  -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport -e frame.len \
  -Y 'tcp.flags.syn==1 && tcp.flags.ack==0'   # every connection attempt

# Every HTTP request: host, method, URI, user-agent
tshark -r case.pcap -T fields -e http.host -e http.request.method \
  -e http.request.uri -e http.user_agent -Y http.request
```

## Display-Filter Fluency

Display filters are the scalpel. The highest-value ones:

| Filter | Surfaces |
| --- | --- |
| `http.request` | Every outbound HTTP request — URIs, hosts, user agents |
| `dns` | All DNS; add `dns.flags.rcode == 3` for NXDOMAIN (DGA tell) |
| `tls.handshake.type == 1` | ClientHello only — SNI, JA3 input, offered ciphers |
| `tls.handshake.type == 2` | ServerHello — chosen cipher, JA3S input |
| `ip.addr == 10.0.0.5` | All traffic to or from a host (`src`/`dst` to pin direction) |
| `tcp.flags.syn==1 && tcp.flags.ack==0` | Connection attempts — scan and beacon cadence |
| `tcp.flags.reset==1` | RSTs — refused/closed, port-scan responses |
| `frame contains "password"` | Byte-string search across payloads (cleartext creds, markers) |
| `tcp.stream eq 7` | Isolate one reassembled conversation by stream index |
| `tcp.analysis.retransmission` | Loss/instability that skews timing analysis |
| `http.response.code == 200 && http.content_type contains "octet-stream"` | File transfers over HTTP |

Chain them: `ip.dst == 185.100.87.0/24 && dns` scopes DNS to one suspect
netblock. `dns.qry.name matches "[a-f0-9]{20,}"` flags long hex labels.

## Zeek: the Workhorse

Zeek turns a pcap into structured, queryable logs — the single highest-leverage
move on any capture bigger than a few thousand packets.

```bash
zeek -r case.pcap
# Or add the community-id field for cross-tool pivoting:
zeek -r case.pcap policy/protocols/conn/community-id-logging
ls   # conn.log dns.log http.log ssl.log x509.log files.log notice.log weird.log ...
```

The log set and what each answers:

| Log | Answers |
| --- | --- |
| `conn.log` | Every flow: duration, orig/resp bytes, state, service — the backbone of beacon and exfil analysis |
| `dns.log` | Every query/response — tunneling, DGA, TXT/NULL abuse |
| `http.log` | Host, URI, method, user-agent, status, referrer |
| `ssl.log` | TLS version, SNI, JA3/JA3S, cert chain, validation status |
| `x509.log` | Certificate subject, issuer, validity, self-signed flag |
| `files.log` | Every file seen on the wire — MIME, size, MD5/SHA1, source flow |
| `notice.log` | Zeek's own detections (SSL::Invalid_Server_Cert, scans, etc.) |
| `weird.log` | Protocol violations — protocol-on-wrong-port, malformed frames |

Mine them with `zeek-cut` (field extraction by name, order-independent):

```bash
# Longest connections first — beacons and tunnels live at the top
cat conn.log | zeek-cut id.orig_h id.resp_h duration orig_bytes resp_bytes \
  | sort -t$'\t' -k3 -rn | head

# Every distinct destination one host reached, with hit counts
cat conn.log | zeek-cut id.orig_h id.resp_h | grep '^10\.0\.0\.5' \
  | sort | uniq -c | sort -rn

# DNS query names + types, to eyeball tunneling and DGA
cat dns.log | zeek-cut query qtype_name answers | sort | uniq -c | sort -rn | head -50

# Pivot a suspicious flow across all logs by its community-id
cat conn.log | zeek-cut community_id id.orig_h id.resp_h service
```

The `community-id` field is the same string across Zeek, Suricata, and many
EDRs for the same flow — use it to line up an alert with the packets.

## Suricata on a pcap

Run signatures offline against the capture to see what a rule set flags:

```bash
# Run ET Open / community rules over the pcap, write structured events
suricata -r case.pcap -S /etc/suricata/rules/suricata.rules -l ./out/
# eve.json holds alerts, plus dns/http/tls/flow records if enabled
```

Extract and rank the alerts:

```bash
jq -c 'select(.event_type=="alert") | {sig:.alert.signature, src:.src_ip, dst:.dest_ip}' \
  out/eve.json | sort | uniq -c | sort -rn
```

Read alerts as leads, not verdicts. A signature hit tells you where to look; it
does not close the case, and its absence does not clear the capture.

## Beacon Detection

Automated callbacks betray themselves in the timing and the shape, not the
content. Look in `conn.log` for a source/destination pair that recurs at a
regular interval, with small and roughly constant request sizes, over a long
span. Human traffic is bursty and varied; a beacon is a metronome.

```bash
# Inter-arrival deltas for one src/dst pair — near-constant gaps = beacon
tshark -r case.pcap -T fields -e frame.time_epoch \
  -Y 'ip.src==10.0.0.5 && ip.dst==185.100.87.202' \
  | awk 'NR>1{print $1-prev} {prev=$1}' | sort -n | uniq -c
```

- **Regular intervals** (e.g. every 60s) with **jitter** (a ±% spread) is the
  classic C2 signature — perfect regularity is rare malware, mild jitter is
  common.
- **Small constant request sizes** with occasional larger responses = check-in
  polling with tasking.
- **Long connection duration** or a flow that reconnects on a fixed cadence for
  hours points to a persistent channel.

Automate the scoring with **RITA** or a `beacon-analysis` tool over Zeek logs —
they compute interval and size consistency across every pair so you are not
eyeballing one at a time:

```bash
rita import --database case --logs ./ && rita view case beacon:'>=90'
```

## DNS Analysis

DNS is the covert channel of choice because it is rarely blocked and often
unlogged. In `dns.log`, two distinct patterns:

**Tunneling** — DNS used as a data pipe:
- High query volume to a single parent domain (thousands of unique subdomains)
- Long labels: `MFRGG43FMQ.tunnel.evil.com`, base32/hex-looking subdomains
- `TXT` and `NULL` record types carrying encoded payload upstream/downstream
- High per-label entropy versus normal English-ish hostnames

```bash
# Subdomain cardinality per parent domain — a tunnel spikes on one domain
cat dns.log | zeek-cut query | rev | cut -d. -f1-2 | rev \
  | sort | uniq -c | sort -rn | head

# TXT queries only — legitimate use is sparse; volume is a flag
cat dns.log | zeek-cut query qtype_name | awk -F'\t' '$2=="TXT"' | wc -l
```

**DGA** — algorithmically generated rendezvous domains:
- High `NXDOMAIN` rate (`rcode` 3) as the malware cycles through dead names
- Random-looking second-level domains with no linguistic structure

```bash
cat dns.log | zeek-cut rcode_name query | awk -F'\t' '$1=="NXDOMAIN"' \
  | wc -l   # a burst of NXDOMAIN from one host is a DGA tell
```

Score label entropy or use a DGA classifier to separate `cdn-3f2a.example`
(benign hash) from `qwzjxkbvmn.info` (generated). Volume plus entropy plus
NXDOMAIN together make the case; any one alone has benign explanations.

## TLS and Encrypted Traffic

You cannot read the plaintext without keys, but the handshake still fingerprints
the client, the server, and the intent. Encryption hides content, not metadata.

- **JA3 / JA3S** (and **JA4/JA4S**) hash the ClientHello / ServerHello
  parameters into a client and server fingerprint. A rare JA3 shared across
  unrelated hosts, or a JA3 matching a known C2 framework, is a strong lead.
  Zeek's `ssl.log` carries `ja3`/`ja3s`; correlate against public and internal
  known-bad lists.
- In `ssl.log` / `x509.log` look for: **self-signed certs**, **SNI that does not
  match the certificate CN/SAN**, **absurd validity windows** (1000-year or
  same-day certs), **empty/garbage subject fields**, and **SNI pointing at
  suspicious or newly-registered domains**.

```bash
# Self-signed or validation-failed TLS, with the SNI and JA3
cat ssl.log | zeek-cut server_name validation_status ja3 ja3s \
  | grep -iv '\bok$' | sort | uniq -c | sort -rn

# SNI vs certificate subject mismatch — join ssl.log and x509.log on cert id
cat x509.log | zeek-cut certificate.subject certificate.issuer \
  certificate.not_valid_before certificate.not_valid_after
```

When you legitimately hold the session keys (a lab detonation with
`SSLKEYLOGFILE` set, or an exported master secret), decrypt in Wireshark:
*Preferences > Protocols > TLS > (Pre)-Master-Secret log filename*, or
`tshark -r case.pcap -o tls.keylog_file:keys.log -Y http2`. Never assume you can
decrypt production TLS you have no keys for — you are fingerprinting, not
reading.

## HTTP and File Carving

Cleartext HTTP (and decrypted TLS) exposes the whole exchange:

- **User-Agent anomalies** — a hardcoded, malformed, or library-default UA
  (`python-requests`, an empty UA, a typo'd browser string) on outbound traffic
  is a common malware tell. Stack UAs and investigate the rare ones.
- **Suspicious URIs** in `http.log` — base64-looking paths, long random query
  strings, `.php` endpoints on a raw IP, or POSTs of opaque blobs.

Carve transferred files and hash them for pivoting:

```bash
# Zeek extracts files automatically when configured; otherwise from files.log:
cat files.log | zeek-cut fuid mime_type filename md5 sha1 tx_hosts rx_hosts

# Carve without Zeek:
foremost -i case.pcap -o carved/          # signature-based file recovery
tcpflow -r case.pcap -o flows/            # reassemble every TCP stream to a file
# NetworkMiner (GUI/CLI) reassembles files, images, and credentials from a pcap
```

Hash every carved artifact and pivot suspicious ones to `analyzing-malware`:
`sha256sum carved/* ` — a file that appeared on the wire and matches nothing
benign is the next sample to detonate.

## Exfiltration Hunting

Data leaving is the outcome that matters most. In `conn.log`, sort by
`orig_bytes` descending — large *outbound* flows are the headline, and the
direction (orig = the internal host sending) is the whole point.

```bash
# Biggest outbound transfers from internal hosts
cat conn.log | zeek-cut id.orig_h id.resp_h resp_p orig_bytes duration \
  | awk -F'\t' '$4>10000000' | sort -t$'\t' -k4 -rn
```

- **Off-hours transfers** — a bulk upload at 03:00 from a workstation that is
  idle by day. Cross the flow timestamps against business hours.
- **Covert channels** — steady ICMP with payload, or DNS carrying upstream data
  (see DNS analysis). Small packets, high count, one destination.
- **Destination reputation** — cloud storage (`*.s3.amazonaws.com`,
  `*.blob.core.windows.net`), paste sites (`pastebin`, `ghostbin`), and
  file-share domains as the *destination* of a large upload from a server that
  has no business reason to use them.

## Protocol Anomalies

Attackers hide traffic on the wrong port and in the wrong protocol:

- **Non-standard ports** — TLS on 8443 or 4443, HTTP on 8080/8888, or C2 on a
  high random port. `conn.log`'s `service` field is Zeek's *detected* protocol,
  independent of port number.
- **Protocol-on-wrong-port** — Zeek's DPI flags SSH on 443, HTTP on 53, or TLS
  on 22 in `conn.log` (`service` disagrees with `id.resp_p`) and in `weird.log`.

```bash
# Detected service does not match the port — tunneling / evasion
cat conn.log | zeek-cut id.resp_p service | awk -F'\t' \
  '($1=="443" && $2!="ssl") || ($1=="53" && $2!="dns")' | sort | uniq -c
```

- **Cleartext credentials** — FTP, Telnet, HTTP Basic, SMTP AUTH, LDAP simple
  bind. `frame contains "PASS "` in Wireshark, or NetworkMiner's credentials
  tab, pulls them straight out.

## Handing Off IOCs

The capture's value is what you extract for reuse. Tier indicators the way you
would from any source — behaviour outlives infrastructure — and route each
output:

- **File signatures** from carved samples — write `.yar` in `writing-yara-rules`
  against structure, not the URI it happened to use.
- **Packaging IOCs, actor pivots, and infrastructure clustering** into a
  finished product — `producing-threat-intelligence`.
- **Turning a traffic pattern into a deployed detection** — `writing-sigma-rules`
  for log-based rules and `engineering-detections` for the broader rule
  pipeline (a Suricata signature for the JA3, a Zeek `notice` for the beacon
  cadence, a Sigma rule for the DNS pattern).
- **The finished write-up** for stakeholders — `reporting-security-findings`.

Record for every indicator: the flow it came from, the timestamp, and your
confidence. An IP with no context is noise to whoever receives it.

## Rationalizations to Reject

- *"It's all TLS, I can't see anything."* JA3/JA3S, SNI, certificate fields, and
  connection timing fingerprint encrypted traffic without decrypting it. The
  metadata is the analysis.
- *"No alerts fired, so it's clean."* Beaconing and DNS tunneling routinely slip
  past default rule sets. Absence of a Suricata hit is not absence of C2.
- *"The pcap is too big to analyze."* Run Zeek, work the logs, and filter down.
  You triage structured logs, not five million raw frames.
- *"There's no C2 traffic here."* Check DNS, ICMP, and long-lived low-volume
  flows before concluding. C2 hides in the channels you did not sort by bytes.
- *"The volume is normal, so no exfil."* Sort by *outbound* bytes and by time.
  A slow drip over days, or one off-hours burst, does not move the average.
- *"That destination is just a CDN / cloud provider."* Cloud storage and CDN
  domains are exactly where modern exfil and C2 hide. Confirm the flow's shape,
  do not wave it through on the domain name.
- *"I'll just look at the payloads."* Truncated snaplen, encryption, and
  reassembly gaps mean payload-first misses the story. Start with the flow
  metadata, then read the streams that earned it.

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills-core/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Command and Control** (TA0011)

- [T1071](https://attack.mitre.org/techniques/T1071/) Application Layer Protocol — see also `analyzing-malware`, `engineering-detections`
- [T1071.004](https://attack.mitre.org/techniques/T1071/004/) DNS — see also `engineering-detections`, `hunting-threats`
- [T1132](https://attack.mitre.org/techniques/T1132/) Data Encoding — see also `transferring-files`, `analyzing-malware`
- [T1568](https://attack.mitre.org/techniques/T1568/) Dynamic Resolution — see also `analyzing-malware`, `hunting-threats`
- [T1573](https://attack.mitre.org/techniques/T1573/) Encrypted Channel — see also `analyzing-malware`, `engineering-detections`

**Exfiltration** (TA0010)

- [T1048](https://attack.mitre.org/techniques/T1048/) Exfiltration Over Alternative Protocol — see also `transferring-files`, `hunting-threats`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- `hunting-threats` — proactive, hypothesis-driven search across many telemetry
  sources, of which network data is one
- `responding-to-incidents` — the incident process this evidence stream feeds
- `analyzing-malware` — detonate the sample to produce traffic, and receive
  carved files from this skill for analysis
- `investigating-aws-incidents` — when the evidence is cloud control-plane logs
  rather than packets
- `writing-yara-rules` — file signatures from carved artifacts
- `producing-threat-intelligence` — packaging extracted IOCs into a product
- `reporting-security-findings` — the stakeholder write-up
- Wireshark / `tshark` and `capinfos` — interactive and scripted dissection
- Zeek with `zeek-cut` and community-id — structured logs from any capture
- Suricata (ET Open / community rules) — offline signature runs over a pcap
- NetworkMiner — file, image, and credential reassembly from captures
- RITA / beacon-analysis — automated beacon scoring over Zeek logs
- `tcpdump` — capture; `editcap` / `mergecap` — split, merge, trim, and convert
