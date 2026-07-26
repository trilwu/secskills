---
name: analyzing-phishing-emails
description: Triage and forensically analyze reported phishing safely — extract the raw message, read the Received chain, verify SPF/DKIM/DMARC, detect display-name and lookalike spoofing, unwrap redirects and SafeLinks/URLDefense, decode quishing QR codes, triage attachments, and pull IOCs for hunting. Use when handed a reported phishing email, a suspicious .eml or .msg file, a set of email headers to analyze, a malicious attachment or link to triage, or a business email compromise or spoofing case.
---

# Analyzing Phishing Emails

An email is a stack of claims — who sent it, where it came from, that its
links are safe — and phishing analysis is checking each claim against evidence
the sender could not forge: the Received chain, the authentication results,
and the true destination of every link and attachment. The From header is a
display, not a fact. Anyone can type any address into it; your job is to find
the evidence that agrees or disagrees.

## When to Use

- A user reports a suspicious email and you need a verdict and IOCs
- You have a `.eml` or `.msg` file to analyze offline
- You are handed raw headers and asked whether a message is spoofed
- A message carries a link or attachment that needs safe triage
- A business email compromise, invoice-fraud, or vendor-impersonation case
- Confirming whether a domain or brand was spoofed against your users

## When NOT to Use

- **You extracted an attachment and need to detonate it** — come here first to
  safely extract and defang it, then hand the payload to `analyzing-malware`
- **The phish already succeeded and you are chasing the mailbox/OAuth
  compromise in the tenant** — use `investigating-m365-entra`
- **You are building the phishing campaign, not analyzing one** — use
  `performing-social-engineering`
- **The broader incident the phish kicked off** — use `responding-to-incidents`
- **Analyzing the callback traffic from a detonated payload** — use
  `analyzing-network-traffic`

## Safe Handling — Do This First

Treat every reported message as live. The failure mode is not misreading a
header; it is clicking a link in a production mail client or double-clicking
an attachment on your own host.

- Never open the message in a live client. Attacker-controlled remote images
  fire a read beacon; one click on a link authenticates you to their harvester.
- Work from the raw source only — the `.eml`/`.msg`, not a forwarded copy.
  Forwarding rewrites headers and strips the evidence you need.
- Defang every indicator before it touches a report, ticket, or chat:
  `http` → `hxxp`, `.` → `[.]`, `@` → `[at]`. So `http://evil.com/login`
  becomes `hxxp://evil[.]com/login`. Defanging prevents an accidental click
  downstream and stops link-preview bots from detonating it for you.
- Extract and detonate only in an isolated VM with no host sharing and
  simulated or monitored egress — see `analyzing-malware` for the build.

## Getting the Raw Message

The visible email is a rendering. You need the source with all headers.

- **Outlook/Exchange**: save as `.msg`, or in OWA use "View message source".
- **Gmail**: "Show original" → Download Original gives a `.eml`.
- **`.msg` → readable**: `msgconvert sample.msg` produces a `.eml` (RFC822).
- **Inspect structure**: `emldump.py sample.eml` lists MIME parts and indices;
  `emldump.py -s 4 -d sample.eml` dumps part 4 (an attachment) without opening
  it. For `.msg`, `oletools`' `msgconvert` or `python-oletools`'s `olefile`.
- **View full headers**: read the top block of the raw file directly, or paste
  into Message Header Analyzer (MHA) / Google's `mha` / MXToolbox Header
  Analyzer for a parsed hop table.

Keep the original file hashed and untouched; work on copies.

## The Received Chain

The `Received:` headers are added by each mail server the message passes
through, newest at the top. Read them **bottom-up**: the bottom-most
`Received` is the originating server — the earliest, least-forgeable hop.

```
Received: from mail.contoso.com (mail.contoso.com [203.0.113.9])
    by mx.recipient.com ... ; Tue, 21 Jul 2026 09:14:02 +0000   <- final hop
Received: from smtp.sketchy-vps.ru ([185.220.101.5])
    by mail.contoso.com ...   ; Tue, 21 Jul 2026 09:13:58 +0000  <- origin
```

- **Trace the originating IP**: the bottom hop's `[bracketed IP]`. Geolocate
  and WHOIS it (`whois 185.220.101.5`), check reputation, and reconcile it
  against the claimed sender. A "From: ceo@contoso.com" that originates on a
  Russian VPS is your finding.
- **Spot forged hops**: attackers prepend fake `Received` lines to fabricate a
  reputable origin. Only hops added by servers you trust are reliable — trust
  breaks at the first server outside your control. A hop that references a
  server not present in the next hop's `by` is invented.
- **Timezone and hop-time anomalies**: hop timestamps should increase upward by
  seconds. Negative deltas, multi-hour jumps, or a mix of implausible
  timezones indicate forgery or relay through odd infrastructure.
- **Reconcile with the claimed sender**: the origin domain, its PTR/rDNS, and
  the `From` domain should tell one coherent story. They usually do not in a
  phish.

## Authentication Results

SPF, DKIM, and DMARC are the forgery-resistant checks. The receiving server
records them in `Authentication-Results`. Read it, and re-verify rather than
trusting a summary.

```
Authentication-Results: mx.recipient.com;
  spf=pass (sender IP is 203.0.113.9) smtp.mailfrom=bounce.contoso.com;
  dkim=pass header.d=contoso.com header.s=selector1;
  dmarc=fail (p=reject sp=reject dis=none) header.from=contoso.com
```

- **SPF** authenticates the *envelope* sender (`Return-Path` / `smtp.mailfrom`
  / `MAIL FROM`), **not** the visible `From`. Values: `pass` (IP is authorized
  for the envelope domain), `fail` (hard `-all` reject), `softfail`
  (`~all`, suspicious but delivered), `neutral`/`none` (no policy). Check the
  domain's record: `dig txt contoso.com` and read the `v=spf1 ...` string.
- **DKIM** is a cryptographic signature over selected headers and the body.
  `dkim=pass` proves the message was signed by the key at `d=`'s selector and
  not modified. The load-bearing question is **alignment**: does `header.d=`
  match the `From` domain? A valid signature from `d=mailer-xyz.com` on a
  message claiming `From: contoso.com` is not contoso. Re-verify with
  `dkimverify < sample.eml` (dkimpy) and fetch the key via
  `dig txt selector1._domainkey.contoso.com`.
- **DMARC** ties SPF/DKIM to the visible `From` via *alignment* and applies the
  domain owner's *policy*. `dmarc=pass` requires SPF **or** DKIM to pass AND be
  aligned with `header.from`. Read the policy: `dig txt _dmarc.contoso.com`
  → `v=DMARC1; p=reject; ...`. `p=reject`/`quarantine` with `dmarc=fail` means
  the owner told you to distrust it.
- **ARC** (`ARC-Seal`/`ARC-Authentication-Results`) preserves upstream auth
  results across forwarders that would otherwise break SPF/DKIM. Use it to see
  how auth looked before a mailing list or gateway relayed the message.
- **Envelope vs header From**: `Return-Path`/envelope-from is what bounces go to
  and what SPF checks; the header `From:` is what the user sees. Phishers make
  them differ — a benign-looking `From` with a throwaway envelope domain that
  happens to pass SPF is the classic pattern.

## Display-Name and Lookalike Spoofing

Much phishing passes authentication because it comes from a *real* mailbox on a
*lookalike* domain. The auth checks pass for that domain; the deception is
visual.

- **Display-name spoofing**: `From: "IT Helpdesk" <random@gmail.com>`. The name
  is a free-text label; read the actual address.
- **Cousin / lookalike domains**: `cont0so.com`, `contoso-support.com`,
  `contoso.co`. Diff against the real domain character by character.
- **Homoglyph / IDN**: Unicode characters that render like ASCII (Cyrillic `а`
  for Latin `a`). Punycode-encoded domains appear in headers as
  `xn--` — e.g. `xn--cntoso-...`. Decode with `idn` /
  `python3 -c "print('xn--80ak6aa92e.com'.encode().decode('idna'))"` and
  compare the rendered form.
- **Reply-To mismatch**: `From: ceo@contoso.com` but
  `Reply-To: ceo.contoso@gmail.com`. The reply silently goes to the attacker —
  a hallmark of BEC.
- **BEC with no payload**: pure text asking for a wire transfer, gift cards, or
  W-2 data. No link, no attachment, nothing to sandbox. The signal is entirely
  in the headers (Reply-To, origin, auth) and the pretext.

## Header Forensics

- **`Message-ID` sanity**: format is `<unique@sending-domain>`. The domain
  should match the sending infrastructure. A `Message-ID` domain that disagrees
  with the origin, or a malformed/duplicated ID, suggests a spoofing tool.
- **`X-Originating-IP`**: some webmail stamps the true client IP here — pivot on
  it, but note it is client-suppliable and can be forged.
- **`X-Mailer` / User-Agent**: reveals the sending client. Bulk-phish kits and
  scripts (`PHPMailer`, `Python`, custom mailers) look nothing like Outlook or
  the claimed sender's normal stack.
- **Mailer fingerprints**: legitimate bulk senders (SendGrid, Amazon SES,
  Mailchimp) add characteristic `X-` headers and `Received` paths. Their
  presence on a "personal" note from your CEO is a contradiction.

## URL Analysis

Every link is a claim about where it goes. Resolve it without visiting it.

- **Unwrap redirects and shorteners**: expand `bit.ly`/`t.co` with
  `curl -sI hxxp://bit[.]ly/xyz` (read `Location:`, do not follow) or a
  preview service. Chase every hop to the real landing page.
- **Decode wrapper rewrites** — the real URL is inside the wrapper:
  - Microsoft **SafeLinks**: `https://*.safelinks.protection.outlook.com/?url=<encoded>&...`
    — URL-decode the `url=` parameter.
  - Proofpoint **URLDefense**: `https://urldefense.com/v3/__<encoded>__;...` —
    decode with the published `urldefense` decoder (v2/v3 schemes differ).
  These wrappers hide the destination; always extract the original.
- **Quishing (QR-code phishing)**: the payload is an image, not a link. Extract
  the image part (`emldump.py -s N -d`), then decode:
  `zbarimg qr.png` or `python3 -c "from PIL import Image; import
  pyzbar.pyzbar as z; print(z.decode(Image.open('qr.png')))"`. Analyze the
  decoded URL like any other.
- **Intent — harvest vs delivery**: a link to a cloned login page (Microsoft,
  DocuSign, a bank) is **credential harvesting**; a link that downloads a file
  is **malware delivery**. They need different responses.
- **Detonate safely**: submit the URL to **urlscan.io** (use unlisted/private
  scans for targeted phish so you don't tip the actor) or a sandbox, and pull
  the real landing page, screenshot, and served content. Extract the landing
  page and any kit files for the IOC set.

## Attachment Analysis

Identify and defang before anything executes.

- **Hash and identify**: `sha256sum att.ext && file att.ext`. Extract with
  `emldump.py -s N -d sample.eml > att.ext` — never by double-clicking.
- **Common delivery wrappers**: HTML smuggling (a `.html` that assembles a
  payload in-browser via a Blob), ISO/IMG/VHD (mount bypasses MOTW), LNK
  shortcuts, OneNote (`.one`) with embedded scripts, and password-protected
  archives (password in the email body defeats gateway scanning).
- **Documents/macros**: `exiftool att.docx` for metadata and authoring
  fingerprints; `oleid att.xls` and `olevba --deobf att.xls` /
  `oledump.py att.doc` for macros; `rtfobj att.rtf` for embedded objects.
- Once identified, **hand the live payload to `analyzing-malware`** for
  sandboxed detonation, unpacking, and C2 extraction. This skill's job is safe
  extraction and triage, not detonation.

## Pulling and Packaging IOCs

Extract a clean, defanged indicator set for blocking and hunting:

- **Sender infrastructure**: originating IP, envelope-from domain, `From`/cousin
  domains, `Reply-To`, `Message-ID` domain, mailer fingerprints.
- **URLs**: the wrapped and unwrapped forms, final landing page, shortener
  chain, and any kit hostnames from urlscan.
- **Hashes**: SHA-256 of every attachment and of decoded/downloaded payloads.
- **Hunting selectors**: subject lines, sender display names, and body
  fingerprints to search the mail gateway and other mailboxes.

Package these for `producing-threat-intelligence` when the phish is part of a
tracked campaign, and for `reporting-security-findings` for the writeup.

## Scoping the Campaign

One report is rarely the only recipient. Find the rest before you close.

- **M365**: `Search-UnifiedAuditLog` and Content Search / `New-ComplianceSearch`
  for the subject, sender, and URL across all mailboxes; hard-delete or
  quarantine matches via `Get-QuarantineMessage` / eDiscovery purge.
- **Mail gateway** (Proofpoint, Mimecast, Defender for O365): search message
  trace / Threat Explorer for the sender domain, URL, and attachment hash to
  enumerate every recipient and whether anyone clicked or replied.
- If any recipient interacted, the phish may have succeeded — pivot to
  `investigating-m365-entra` for tenant-side hunting (sign-ins, inbox rules,
  OAuth grants) and to `responding-to-incidents` for the broader response.

## Rationalizations to Reject

- *"SPF passed, so it's legitimate."* SPF authenticates the envelope domain,
  not the visible `From`. A passing SPF on a lookalike or throwaway envelope
  domain is exactly what a competent phish shows. Check DMARC alignment.
- *"DKIM is valid, so it's from them."* A valid signature only proves the `d=`
  domain signed it. If `d=` isn't aligned with the `From` domain, it's signed
  by someone else. Alignment is the question, not signature validity.
- *"No attachment or link, so it's harmless."* BEC and payment-fraud phish
  carry neither — the weapon is the pretext and the Reply-To. Read the headers.
- *"DMARC failed but it was delivered, so it's fine."* Delivery reflects the
  receiver's enforcement config, not the message's legitimacy. `dmarc=fail`
  with `p=reject` is the sender's domain telling you to distrust it.
- *"The From address is our real domain, so it's internal."* The `From` header
  is free text. Without aligned SPF/DKIM and a plausible origin hop, an
  internal-looking From means nothing.
- *"I'll just click the link to see where it goes."* Clicking authenticates you
  to a harvester or fires a beacon. Resolve URLs with headers-only requests,
  wrapper decoders, and urlscan — never a live browser.
- *"The gateway let it through, so it's clean."* Gateways miss lookalike
  domains, freshly registered infrastructure, HTML smuggling, and password-
  protected archives by design. A delivered message is not a vetted one.

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Reconnaissance** (TA0043)

- [T1598](https://attack.mitre.org/techniques/T1598/) Phishing for Information — see also `performing-social-engineering`

**Initial Access** (TA0001)

- [T1566](https://attack.mitre.org/techniques/T1566/) Phishing — see also `performing-social-engineering`
- [T1566.001](https://attack.mitre.org/techniques/T1566/001/) Spearphishing Attachment — see also `performing-social-engineering`, `analyzing-malware`
- [T1566.002](https://attack.mitre.org/techniques/T1566/002/) Spearphishing Link — see also `performing-social-engineering`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- `analyzing-malware` — sandboxed detonation and C2 extraction of attachments
- `investigating-m365-entra` — tenant-side hunting when the phish succeeded
- `performing-social-engineering` — building phishing campaigns (offensive)
- `analyzing-network-traffic` — callback traffic from a detonated payload
- `producing-threat-intelligence` — pivoting IOCs into tracked campaigns
- `reporting-security-findings` — writing up the triage and verdict
- `oletools` (olevba, oledump, oleid, rtfobj, msgconvert), `emldump.py`
  (DidierStevens suite), and `exiftool` for message and attachment parsing
- Message Header Analyzer (MHA) and MXToolbox for parsing the Received chain
  and querying SPF/DKIM/DMARC records
- urlscan.io and VirusTotal for URL/file detonation and reputation
- PhishTool for guided end-to-end phishing analysis and reporting
