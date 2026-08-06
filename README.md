# SecSkills

**82 security skills for [Claude Code](https://claude.com/claude-code) that
encode the *judgment* professionals bring — not another wrapper around a
scanner.** Offense, defense, and the reverse-engineering / code-audit core both
sides share. Every skill fact-checked against primary sources.

Claude already knows what `nmap -sV` does. What it does not reliably hold is the
discipline: trace a finding to demonstrated impact before you report it,
capture memory before someone reimages the box, refuse to ship a detection that
was never tested against production noise, notice the honeypot before you touch
it. SecSkills is that discipline, written down and routed to the moment it
applies.

Three plugins in one marketplace — install only the side you work:

| Plugin | Skills | For |
| --- | --- | --- |
| **`secskills-offense`** | 40 | Red team, pentest, offensive AppSec |
| **`secskills-defense`** | 22 | DFIR, SOC, detection engineering, threat intel |
| **`secskills-core`** | 30 | Reverse engineering, code/crypto audit, AI/MCP security, reporting — shared by both |

```bash
/plugin marketplace add trilwu/secskills

# Offensive — red team / pentest / offensive AppSec
/plugin install secskills-offense@secskills-marketplace
/plugin install secskills-core@secskills-marketplace

# Defensive — DFIR / SOC / detection
/plugin install secskills-defense@secskills-marketplace
/plugin install secskills-core@secskills-marketplace

/reload-plugins
```

Skills reference their siblings by name across plugins; a hand-off to a skill
you did not install is an inert mention, so nothing breaks — you get the skills
you have.

---

## Who it's for

SecSkills is built for four working roles. Each gets a coherent toolkit, not a
grab-bag.

### 🔴 Red team / pentest → `offense` + `core`

Full attack-chain methodology with the tradecraft judgment that separates a
finding from a footgun: recon and enumeration, Active Directory and Entra ID
(Kerberos delegation, AD CS ESC1–16, DCSync), cloud and managed Kubernetes,
container escapes, mobile, wireless, and web/API/auth exploitation. Plus the
engagement discipline most collections skip — **`recognizing-deception`**
(spot the honeypot/canary before you trip it), **`maintaining-engagement-state`**
(credential provenance and the cleanup register that survives a context
window), and **`reporting-security-findings`**.

### 🛡️ AppSec / code review → `core` (+ `offense` to prove impact)

Source-audit methodology with a four-question verification gate, PR review that
reads the lines a change *removed*, cryptography-misuse review, supply-chain and
CI/CD auditing, and AI/LLM + MCP security. Language-agnostic by default, with
**`auditing-php-applications`** for PHP's specific footguns (unserialize/`phar://`
POP chains, type-juggling auth bypass, `php://` wrappers) and
**`hunting-web-backdoors`** for planted webshells. Reach into `offense` when you
need to demonstrate the bug, not just describe it. And when the target is big
enough to warrant a campaign, **`orchestrating-vulnerability-research`** runs the
hunt as an adversarial loop — builders hunt each slice, an independent critic
tries to *refute* every candidate against the running target, and nothing counts
until it is proven, not plausible.

### 🔵 DFIR / incident response → `defense` + `core`

Preserve-first response: memory/disk/network forensics, malware and shellcode
analysis, Windows endpoint DFIR, Linux persistence hunting, and cross-cloud
incident investigation for **AWS, Azure, GCP, and M365/Entra** — each built
around the audit-log defaults that decide whether a question is even
answerable. Backed by the RE core (native, Go/Rust/.NET, iOS, firmware,
packers).

### 🟣 SOC / detection engineering → `defense` + `core`

The high-volume work, done with base-rate discipline:
**`triaging-security-alerts`** (the true / benign-true / false-positive
distinction that keeps a detection program alive), detection-as-code across
Sigma/YARA/Suricata with *real* false-positive analysis, hypothesis-driven
threat hunting, risk-based vulnerability management (KEV + EPSS, not raw CVSS),
and finished threat intelligence with attribution discipline.

Cloud and Kubernetes are covered from **both** sides — `exploiting-cloud-platforms`
/ `attacking-eks-gke-aks` for red, `hardening-cloud-posture` / `defending-kubernetes`
/ `investigating-*-incidents` for blue — so purple-team work stays in one
vocabulary.

## What makes a skill

Each skill is a methodology, not a command dump, with three things a cheat
sheet does not give you:

- **An explicit scope and hand-off.** Every skill says when to use a *different*
  one, named in backticks. That is how 92 skills compose instead of colliding.
- **A `Rationalizations to Reject` section** — the plausible-sounding shortcuts
  that cause missed findings and bad calls, each with why it is wrong. This is
  the highest-value part of most skills; it is the judgment a command list
  cannot carry.
- **Two tiers that stay out of your way.** *Domain* skills carry methodology for
  a whole area and trigger on plain-language requests. *Procedure* skills cover
  one exact target-and-toolchain that is rare and unrecoverable from general
  knowledge — reversing a Flutter app with blutter, say — and load only when
  their identifying evidence is present. Neither costs context until it applies.

## Every skill is fact-checked — and dated

**82 of the 92 skills have been verified line-by-line against primary sources** —
vendor docs, RFCs, tool source — and carry a `verified:` date in frontmatter.
This is the differentiator: it is the opposite of confidently-wrong AI output.

The 10 most recently added skills (the reverse-engineering and agent-vetting
additions) are **unverified drafts** — well-formed and passing CI, but not yet
driven through the line-by-line accuracy pass. They carry no `verified:` date,
which is exactly how to tell them apart. Treat their specific tool flags and
version claims as provisional until that pass lands.

```bash
python3 scripts/validate.py --strict                 # "Fact-checked ...: 82/92"
grep -L "^verified:" secskills-*/skills/*/SKILL.md   # the 10 unverified drafts
```

What that pass caught is why it exists. The first sampled dozen skills held
**31 factual errors — ~2.6 per skill** — so the whole collection was driven
through the same pass. Cross-cutting sweeps then found the high-impact ones:
CrackMapExec archived since 2023 (14 dead invocations → NetExec/`nxc`), the
retired AzureAD PowerShell module (→ Microsoft Graph), Volatility's entry point
wrong in ~40 commands (`vol`, not `volatility3`), a fabricated Sigma `utf8`
modifier, and stale M365 audit-log retention that would read an empty 90-day
window as "no activity" when six months of history existed.

Two honest caveats:

- **`verified:` is dated, not eternal.** Tool flags, CVE version bounds,
  retention windows, and API paths drift. Trust the methodology — the
  sequencing, the scope, the *Rationalizations to Reject* — and re-confirm any
  specific before it lands in a deliverable. The re-verification method is
  itself a skill: `.claude/skills/verifying-skill-accuracy`.
- **CI checks form, not truth.** `validate.py`, `sync_attack.py`, and
  `run_evals.py` verify structure, the ATT&CK index, and routing against
  self-authored cases. A green run means well-formed; the `verified:` dates are
  the accuracy signal.

## Skills

### Code and application security

| Skill | Use it for |
| --- | --- |
| `auditing-code-for-vulnerabilities` | Full source audit: context → attack surface → bug-class hunt → variant analysis, with a four-question verification gate |
| `orchestrating-vulnerability-research` | Run a discovery campaign across a codebase, binary, or live target: split the surface into slices, hunt each with a builder agent, and have a separate critic refute every candidate against the running artifact before it counts |
| `auditing-php-applications` | PHP-specific bugs: unserialize/`phar://` POP chains, type juggling, `php://` wrappers, superglobal trust, WordPress/Magento/Laravel |
| `hunting-web-backdoors` | Sweep a web tree for planted webshells: static deobfuscation, append-infections, known shell families as leads |
| `reviewing-code-changes` | Security review of a diff, branch, or PR — including the lines the change *removed* |
| `testing-web-applications` | Black-box web testing: injection, auth, JWT, SSRF, uploads |
| `testing-apis` | REST and GraphQL: BOLA, mass assignment, rate limits |
| `reviewing-cryptography` | Crypto misuse: AEAD, nonces, key management, timing, TLS, JWT |
| `auditing-supply-chain` | Dependencies, malicious packages, GitHub Actions, SBOM, provenance |
| `auditing-mcp-servers` | Reviewing an MCP server: tool-definition injection, token passthrough, per-tool authorization |
| `vetting-agent-extensions` | Deciding whether a third-party skill, plugin, or MCP server is safe to install — context-loaded content as injection surface, config that runs on startup, trust verdict |
| `securing-ai-systems` | LLM and agentic security: prompt injection, tool authority, RAG isolation, the lethal trifecta |
| `exploiting-web3-smart-contracts` | Solidity and smart contract auditing |

### Defense, detection, and response

| Skill | Use it for |
| --- | --- |
| `triaging-security-alerts` | Work an alert queue to a defensible disposition: true / benign-true / false-positive, base rates, time-boxing |
| `responding-to-incidents` | DFIR: evidence preservation, artifact analysis, timelining, scoping, containment |
| `analyzing-malware` | Containment-first sample analysis, config and C2 extraction, IOC and YARA output |
| `engineering-detections` | Sigma/YARA/Suricata authoring with real false-positive analysis |
| `hunting-threats` | Hypothesis-driven hunting with stack counting and outlier analysis |
| `managing-vulnerabilities` | Risk-based remediation order: KEV + EPSS + reachability + asset value, SSVC — not raw CVSS |
| `producing-threat-intelligence` | Indicator pivoting, actor/campaign tracking, attribution discipline, finished intel products |
| `reporting-security-findings` | Severity, proof of concept, report structure, disclosure |

### Offensive operations

| Skill | Use it for |
| --- | --- |
| `recognizing-deception` | Spot honeypots, canary tokens, and decoy accounts before you trip them |
| `maintaining-engagement-state` | Credential provenance, access inventory, and the cleanup register across a multi-day engagement |
| `performing-reconnaissance` | OSINT, subdomain enumeration, attack surface mapping |
| `enumerating-network-services` | Service enumeration and exploitation |
| `attacking-active-directory` | Kerberoasting, BloodHound, DCSync, lateral movement |
| `escalating-linux-privileges` | SUID, capabilities, sudo, cron, kernel |
| `escalating-windows-privileges` | Services, DLL hijacking, tokens, potato attacks |
| `exploiting-containers` | Docker and Kubernetes escapes and misconfiguration |
| `exploiting-cloud-platforms` | AWS, Azure, GCP enumeration and abuse |
| `testing-mobile-applications` | Android and iOS assessment |
| `attacking-wireless-networks` | Wi-Fi attacks and capture |
| `cracking-passwords` | Hash identification and offline cracking |
| `establishing-persistence` | Post-exploitation persistence |
| `transferring-files` | File transfer and exfiltration channels |
| `performing-social-engineering` | Authorized phishing and pretexting |
| `exploiting-memory-corruption` | Turn a crash into a working exploit: ROP, heap grooming, defeating ASLR/NX/canary/RELRO |
| `testing-thick-clients` | Desktop fat-client testing: non-HTTP proxying, config/memory secrets, client-side trust bypass, two-tier DB access |
| `attacking-hardware-interfaces` | Physical device surface: UART/JTAG, SPI flash-off, secure-boot triage, sub-GHz SDR replay feasibility |

### Web and API procedure skills

| Skill | Triggers on |
| --- | --- |
| `exploiting-ssrf` | Any feature that fetches a user-supplied URL; webhooks, importers, renderers |
| `exploiting-deserialization` | `rO0AB`, `AAEAAAD`, `O:`, `gAJ` in a cookie or parameter |
| `attacking-graphql` | `/graphql`, a `query`/`mutation` body, `{data, errors}` envelope |
| `attacking-grpc-protobuf` | HTTP/2 with `application/grpc`, opaque binary bodies |
| `attacking-jwt` | A token starting `eyJ` in a header, cookie, or body |
| `attacking-oauth-oidc` | `/authorize`, `redirect_uri`, `state=`, "Sign in with X", OIDC discovery |
| `attacking-saml` | `SAMLResponse`, `<saml:Assertion>`, `/saml/acs`, IdP federation |
| `exploiting-xxe` | An endpoint parsing XML, SOAP, SVG, or Office (OOXML) files |

### Binary and runtime procedure skills

`analyzing-binaries` is the native reverse-engineering domain skill —
triage, disassembly (Ghidra/radare2/IDA), and instrumentation — that the
language- and framework-specific procedures below hand back to.

| Skill | Triggers on |
| --- | --- |
| `analyzing-binaries` | An unknown native executable: format triage, disassembly, dynamic instrumentation |
| `analyzing-go-binaries` | `runtime.main`, `go:buildid`, a huge "stripped" binary |
| `analyzing-rust-binaries` | `rustc version`, `core::panicking`, `_R`/`_ZN` symbols |
| `analyzing-dotnet-assemblies` | Managed PE, mangled names, `Assembly.Load` loaders |
| `analyzing-macos-binaries` | A `.app`/Mach-O on macOS: entitlements, XPC auth, dylib hijack, TCC |
| `unpacking-protected-binaries` | High entropy, three imports, `UPX0`/`.vmp0` sections |
| `devirtualizing-vm-protected-code` | A giant fetch-decode-dispatch loop: VMProtect/Themida/custom VM lifting |
| `reversing-obfuscated-javascript` | A minified/obfuscated web bundle, `_0x` names, a reachable `.js.map` |
| `reversing-browser-extensions` | A CRX/XPI: manifest permissions and the page↔content↔background trust boundary |
| `reversing-network-protocols` | A proprietary binary protocol Wireshark shows as raw bytes |
| `diffing-binary-patches` | Two versions of a DLL/ELF: find the fixed bug for 1-day analysis |

### Mobile procedure skills

Narrow by design — each triggers on the artifacts or the symptom that
identifies the situation, and hands back to the domain skill when done.

| Skill | Triggers on |
| --- | --- |
| `bypassing-mobile-pinning` | TLS handshake alert, empty proxy, "network error" with the proxy on |
| `bypassing-root-jailbreak-detection` | App exits on a rooted device, or dies when Frida attaches |
| `analyzing-ios-binaries` | IPA with `cryptid 1`, Mach-O, `class-dump` returning nothing |
| `testing-mobile-ipc` | Exported components, deep links, URL schemes, content providers |
| `reversing-flutter-apps` | `libapp.so`, `libflutter.so`, `flutter_assets/` |
| `reversing-react-native-apps` | `index.android.bundle`, `libhermes.so`, `main.jsbundle` |
| `reversing-unity-il2cpp` | `global-metadata.dat`, `libil2cpp.so`, `Assembly-CSharp.dll` |
| `reversing-xamarin-maui` | `libmonodroid.so`, `assemblies.blob`, `libxamarin-app.so` |

### Active Directory and identity procedure skills

| Skill | Triggers on |
| --- | --- |
| `abusing-adcs` | A CA in the domain, `certipy find` flagging a template, ESC1–ESC16 |
| `attacking-kerberos-delegation` | Unconstrained/constrained/RBCD delegation, `GenericWrite` over a computer |
| `attacking-entra-id` | Entra ID / Azure AD as the target: tokens, PRTs, consent grants, hybrid sync |

### Cloud, container, and Kubernetes skills

| Skill | Triggers on |
| --- | --- |
| `attacking-eks-gke-aks` | A managed Kubernetes cluster: pod-to-cloud IMDS, IRSA/Workload Identity, k8s RBAC |
| `defending-kubernetes` | Hardening/monitoring a cluster: RBAC by capability, Pod Security Admission, audit logging |
| `hardening-cloud-posture` | Proactive AWS/Azure/GCP posture: attack-path ranking, CSPM triage, org guardrails |
| `attacking-serverless` | Lambda / Azure Functions / Cloud Functions / Workers; event injection, execution-role abuse |
| `abusing-ci-cd-oidc` | GitHub Actions / GitLab CI / Jenkins, OIDC federation with broad trust policies |
| `escaping-hardened-containers` | Seccomp on, capabilities dropped, `--privileged` absent, obvious escapes blocked |

### DFIR and detection procedure skills

| Skill | Triggers on |
| --- | --- |
| `analyzing-memory-images` | A RAM capture to work with Volatility: injected code, in-memory creds |
| `analyzing-disk-images` | An `.E01`/`.dd`/`.vmdk`: deleted-file recovery, carving, super-timeline |
| `investigating-windows-endpoints` | A Windows host: EVTX/Sysmon, prefetch, amcache, `$MFT`/USN, persistence |
| `investigating-m365-entra` | A cloud-only compromise: UAL, sign-in logs, OAuth consent grants, mailbox rules |
| `investigating-aws-incidents` | Exposed AWS keys, anomalous CloudTrail, a GuardDuty finding, IAM persistence |
| `investigating-azure-incidents` | Anomalous Azure Activity Log, a Defender for Cloud alert, service-principal abuse |
| `investigating-gcp-incidents` | A leaked service-account key, GCP audit-log gaps, a Security Command Center finding |
| `analyzing-network-traffic` | A `.pcap`/`.pcapng`: C2 beacons, DNS tunneling, JA3/TLS, exfil, file carving |
| `analyzing-phishing-emails` | A reported `.eml`/`.msg`: headers, SPF/DKIM/DMARC, links, attachments |
| `analyzing-shellcode` | A raw position-independent blob: decoder stubs, PEB-walk/API-hash, stagers |
| `analyzing-linux-persistence` | Finding how an attacker persisted on a Linux host across every init path |
| `writing-sigma-rules` | Authoring a portable Sigma rule: field taxonomy, modifiers, backend conversion |
| `writing-yara-rules` | Authoring a durable YARA rule for a file/memory artifact or malware family |

### Specialist procedure skills

| Skill | Triggers on |
| --- | --- |
| `testing-ics-ot-protocols` | Modbus/502, DNP3, S7comm/102, OPC UA, BACnet on a SCADA/OT network |
| `analyzing-firmware-images` | A firmware update file or dump: `binwalk`, filesystem carving, cross-arch emulation |
| `attacking-bluetooth-nfc` | BLE GATT enumeration, NFC/MIFARE card cloning, RF sniffing |

### Navigation

| Skill | Use it for |
| --- | --- |
| `mapping-attack-techniques` | Resolving an ATT&CK ID, tactic, or intel report to the skill that holds the procedure; purple-team loop and coverage reporting |

Techniques are indexed in [`secskills-core/ttp-index.json`](secskills-core/ttp-index.json)
(143 mapped, spanning all three plugins), which generates the `## ATT&CK
Coverage` section in each skill. CI fails if a section drifts from the index,
and skills that use a different framework — ATLAS for AI, the Mobile matrix,
CWE for code-level work — are declared as such rather than counted as coverage.

## In practice

**Hunt a hacked site (DFIR / AppSec)**

```
"This WordPress site is redirecting to spam and grep for eval comes back empty."
```

Explains that an empty grep is not a clean tree — concatenation and callback
sinks evade it — then diffs against a pristine copy, checks `functions.php` for
append-infection, and decodes any obfuscation *statically*, never by running it.

**Work an alert (SOC)**

```
"EDR critical: a signed vendor binary opened an LSASS handle at 03:00, 47th time."
```

Reads it as a likely *benign* true positive, warns against filing it as a false
positive (which weakens a working rule), and sends an authorized-context filter
to detection engineering instead.

**Drive a domain (Red team)**

```
"BloodHound flags svc_backup_admin — DA, SPN set, but no logon history. Roast it?"
```

Flags the profile as a probable honeyuser whose Kerberoast raises a
high-fidelity alert, and routes around it — recording provenance as it goes.

**Investigate GCP (DFIR)**

```
"A leaked service-account key was used. Did they read our storage buckets?"
```

Answers with the audit-log defaults: GCP Data Access logging is off unless
enabled in advance, so it reports a *visibility gap*, not "no exfiltration."

**Assess an AI feature (AppSec)**

```
"Review this RAG agent for prompt injection."
```

Checks whether the lethal trifecta closes — private data, untrusted content, and
egress in one agent — before any payload, and refuses prompt-level defenses as a
control.

**Run a discovery campaign (AppSec / Red team)**

```
"Find previously-unknown bugs in this service — fan out agents, and don't count anything you can't prove."
```

Splits the attack surface into independent slices and hunts each with its own
builder agent, then hands every candidate to a *separate* critic that tries to
refute it against the running target — a reproduced trigger or a live response,
never the hunter's own writeup. It kills the plausible-but-safe candidate (the
`subprocess` call that looks injectable but passes an argv list, so nothing
executes) and confirms the real ones, then reconciles across slices to surface
the chain no single hunter could see.

## Where this fits

SecSkills is domain expertise, not a scanner. It complements first-party tooling
rather than replacing it:

| Layer | Tool |
| --- | --- |
| While Claude writes code | [`security-guidance`](https://code.claude.com/docs/en/security-guidance) plugin |
| One-pass branch review | Built-in `/security-review` |
| Deep multi-agent scan | [`claude-security`](https://code.claude.com/docs/en/claude-security) plugin |
| **Domain methodology and judgment** | **SecSkills** |
| In CI | Your existing SAST and dependency scanners |

The scanners find what they have rules for; the skills supply the reasoning
around them.

## Requirements

Claude Code, and the tools a given technique calls for (`nmap`, `semgrep`,
`vol` (Volatility 3), `capa`, `ghidra`, …) installed separately. The plugin
supplies knowledge and method, not binaries.

## Antivirus false positives

Some skills document attacker artefacts verbatim — webshell one-liners,
download cradles, persistence snippets. Antivirus engines match on file
*content*, not extension, so a Markdown file quoting China Chopper looks the
same to a signature scanner as a live `.php` webshell. Microsoft Defender has
quarantined skill files under names like `Backdoor:PHP/Chopper.B!dha` and
`Backdoor:PHP/Perhetshell.B!dha`.

These are false positives. Nothing in this repo executes: the files are
Markdown, there are no binaries, no packed or encoded payloads, and no
installer. The detections were signature hits on documented indicators —
including, at one point, on `hunting-web-backdoors`, a *defensive* skill
flagged for containing the IOC it teaches you to hunt.

Where a payload string was getting whole skills quarantined, the identifiers
are now bracket-broken — `syst[e]m`, `ev[a]l`, `$_G[E]T` — with a note at each
site. Detection regexes and hunting patterns are left intact, since breaking
those would make the defensive skills wrong.

If your scanner still quarantines a file, exclude the plugin path rather than
disabling protection:

```powershell
Add-MpPreference -ExclusionPath "$env:USERPROFILE\.claude\plugins"
```

Please open an issue with the detection name and file path if you hit a new
one — that's what pins down which string is responsible.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the authoring standard. Before
opening a PR:

```bash
python3 scripts/validate.py --strict     # frontmatter, sections, manifests, verified count
python3 scripts/sync_attack.py --check   # ATT&CK sections match the index
python3 scripts/run_evals.py --check     # every skill has a trigger eval
python3 scripts/build_site.py --check    # the docs/ site is in sync
```

CI runs the same checks. Every new skill ships with at least one
trigger-accuracy case in [`evals/cases.jsonl`](evals/README.md) — a realistic
request labelled with the skill that should activate, plus a `trap_for` case
where it sits near an existing skill, so routing stays correct as the collection
grows. Two repo-local skills, `authoring-security-skills` and
`verifying-skill-accuracy`, encode the standard and the fact-checking method.
Contributions must serve authorized security work; no working malware, implants,
or evasion tooling.

## Legal

**For authorized use only.** Penetration testing with written permission,
in-scope bug bounty work, research on systems you control, education and CTFs,
and defensive operations.

Not for unauthorized access, illegal activity, or violating terms of service.
You are responsible for obtaining authorization and complying with applicable
law. Provided as-is, without warranty; the authors accept no liability for
misuse.

## Website

A browsable site — role-based prompts, a searchable catalog, and a page per
skill with its full methodology — is generated from this repo into
[`docs/`](docs/) by `scripts/build_site.py` (stdlib only, no drift: CI fails if
it is stale). Serve it with GitHub Pages → Settings → Pages → Source: `main`
/ `docs`.

## License

MIT — see [LICENSE](LICENSE).

## Related work

Worth knowing about, and in several cases worth installing alongside this:

- [trailofbits/skills](https://github.com/trailofbits/skills) — deep code-audit
  workflows, Semgrep/CodeQL rule authoring, verification, and secure contracts
- [anthropics/claude-plugins-official](https://github.com/anthropics/claude-plugins-official)
  — the `security-guidance` and `claude-security` plugins
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/),
  [MITRE ATT&CK](https://attack.mitre.org/),
  [Sigma](https://github.com/SigmaHQ/sigma),
  [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
