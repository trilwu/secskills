# SecSkills

**Security skills for [Claude Code](https://claude.com/claude-code) — 72 skills covering both halves of security work: finding and exploiting weaknesses, and finding and fixing them in code.**

The collection ships as three plugins in one marketplace so you install only
the side you work: **`secskills-offense`** (36 skills), **`secskills-defense`**
(17 skills), and **`secskills-core`** (19 dual-use skills — reverse
engineering, code/crypto review, AI security, ATT&CK mapping, reporting).
Core is the shared foundation both sides reference; install it alongside
either.

```bash
/plugin marketplace add trilwu/secskills

# Red team / pentest
/plugin install secskills-offense@secskills-marketplace
/plugin install secskills-core@secskills-marketplace

# Blue team / DFIR
/plugin install secskills-defense@secskills-marketplace
/plugin install secskills-core@secskills-marketplace

# Or all three
/reload-plugins
```

Skills reference their siblings by name across plugins; a hand-off to a skill
you did not install is just an inert mention, so nothing breaks — you simply
get the skills you have.

---

## What this is

Claude already knows what `nmap -sV` does. What it does not reliably do is
*hold the discipline* — trace a finding to a demonstrated impact before
reporting it, preserve memory before someone reimages the box, refuse to ship
a detection rule that was never tested against production noise.

SecSkills encodes that discipline. Each skill is a methodology with an
explicit scope, an explicit hand-off to the right sibling skill, and a
**Rationalizations to Reject** section listing the plausible-sounding
shortcuts that cause missed findings and bad calls.

Skills come in two tiers. **Domain skills** carry methodology for a whole area
and trigger on plain-language requests. **Procedure skills** cover one
target-and-toolchain combination that is rare, exact, and unrecoverable from
general knowledge — reversing a Flutter app with blutter, for instance. A
generic mobile skill cannot hold that without bloating for everyone else, and
the person who needs it needs far more than a generic skill would carry. Both
load only when relevant, so neither costs anything until it applies.

## Verification status

**Every skill has been fact-checked against primary sources** — vendor docs,
RFCs, tool source, upstream references — and carries a `verified:` date in its
frontmatter. `validate.py` reports the count on every run:

```bash
python3 scripts/validate.py --strict                 # "Fact-checked ...: 79/79"
grep -L "^verified:" secskills-*/skills/*/SKILL.md   # any unverified (none today)
```

What that verification found and fixed, so you know what "verified" is worth
here:

- The first sampled pass over 12 skills found **31 factual errors across 11 of
  them** — ~2.6 per skill — which is why the whole collection was then driven
  through the same pass rather than trusted as written.
- Cross-cutting class sweeps caught the highest-impact defects: CrackMapExec
  archived since 2023 (14 invocations, now NetExec/`nxc`), the retired AzureAD
  PowerShell module (now Microsoft Graph), Volatility's entry point wrong in
  ~40 commands (`vol`, not `volatility3`), a fabricated Sigma `utf8` modifier,
  and stale M365 audit-log retention that would read as "no activity" over a
  gap that in fact had six months of history.

**`verified:` is dated, not eternal.** It means every checkable claim was true
against a primary source *on that date*. Tool flags, CVE version bounds,
retention windows, and API paths drift; re-verify specifics before you rely on
them in a deliverable, and treat the methodology — the sequencing, scope, and
*Rationalizations to Reject* — as the durable part. The re-verification
procedure is itself a skill: `.claude/skills/verifying-skill-accuracy`.

Note that CI still checks **form, not truth** — `validate.py`, `sync_attack.py`,
and `run_evals.py` verify structure, the ATT&CK index, and routing against
self-authored cases. A green run means well-formed, not correct; the `verified:`
dates are the accuracy signal.

What this means in practice:

- **Trust the methodology; verify every specific.** The sequencing, the scope
  boundaries, and the *Rationalizations to Reject* sections are the durable
  part. Any command, ID, or field name is a starting point to confirm, not a
  fact to paste into a deliverable.
- **Be strictest with the defense skills.** A wrong flag in an offensive skill
  fails loudly when you run it. A misread forensic artifact fails silently into
  an incident timeline that lawyers and regulators later read.
- **CI does not check accuracy.** `validate.py`, `sync_attack.py`, and
  `run_evals.py` verify formatting, cross-references, ATT&CK-index consistency,
  and routing against self-authored eval cases. All of that is internal
  consistency. None of it touches ground truth.

## Skills

### Code and application security

| Skill | Use it for |
| --- | --- |
| `auditing-code-for-vulnerabilities` | Full source audit: context → attack surface → bug-class hunt → variant analysis, with a four-question verification gate |
| `reviewing-code-changes` | Security review of a diff, branch, or PR — including the lines the change *removed* |
| `testing-web-applications` | Black-box web testing: injection, auth, JWT, SSRF, uploads |
| `testing-apis` | REST and GraphQL: BOLA, mass assignment, rate limits |
| `reviewing-cryptography` | Crypto misuse: AEAD, nonces, key management, timing, TLS, JWT |
| `auditing-supply-chain` | Dependencies, malicious packages, GitHub Actions, SBOM, provenance |
| `securing-ai-systems` | LLM and agentic security: prompt injection, tool authority, RAG isolation, MCP review |
| `exploiting-web3-smart-contracts` | Solidity and smart contract auditing |

### Defense, detection, and response

| Skill | Use it for |
| --- | --- |
| `responding-to-incidents` | DFIR: evidence preservation, artifact analysis, timelining, scoping, containment |
| `analyzing-malware` | Containment-first sample analysis, config and C2 extraction, IOC and YARA output |
| `analyzing-binaries` | Reverse engineering: triage, disassembly, instrumentation, firmware |
| `engineering-detections` | Sigma/YARA/Suricata authoring with real false-positive analysis |
| `hunting-threats` | Hypothesis-driven hunting with stack counting and outlier analysis |
| `producing-threat-intelligence` | Indicator pivoting, actor/campaign tracking, attribution discipline, finished intel products |
| `reporting-security-findings` | Severity, proof of concept, report structure, disclosure |

### Offensive operations

| Skill | Use it for |
| --- | --- |
| `performing-reconnaissance` | OSINT, subdomain enumeration, attack surface mapping |
| `enumerating-network-services` | Service enumeration and exploitation |
| `attacking-active-directory` | Kerberoasting, BloodHound, DCSync, lateral movement |
| `escalating-linux-privileges` | SUID, capabilities, sudo, cron, kernel |
| `escalating-windows-privileges` | Services, DLL hijacking, tokens, UAC |
| `exploiting-containers` | Docker and Kubernetes escapes and misconfiguration |
| `exploiting-cloud-platforms` | AWS, Azure, GCP enumeration and abuse |
| `testing-mobile-applications` | Android and iOS assessment |
| `attacking-wireless-networks` | Wi-Fi attacks and capture |
| `cracking-passwords` | Hash identification and offline cracking |
| `establishing-persistence` | Post-exploitation persistence |
| `transferring-files` | File transfer and exfiltration channels |
| `performing-social-engineering` | Authorized phishing and pretexting |

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

| Skill | Triggers on |
| --- | --- |
| `analyzing-go-binaries` | `runtime.main`, `go:buildid`, a huge "stripped" binary |
| `analyzing-rust-binaries` | `rustc version`, `core::panicking`, `_R`/`_ZN` symbols |
| `analyzing-dotnet-assemblies` | Managed PE, mangled names, `Assembly.Load` loaders |
| `unpacking-protected-binaries` | High entropy, three imports, `UPX0`/`.vmp0` sections |

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
| `abusing-adcs` | A CA in the domain, `certipy find` flagging a template, ESC1-ESC16 |
| `attacking-kerberos-delegation` | Unconstrained/constrained/RBCD delegation, `GenericWrite` over a computer |
| `attacking-entra-id` | Entra ID / Azure AD as the target: tokens, PRTs, consent grants, hybrid sync |

### Cloud and container procedure skills

| Skill | Triggers on |
| --- | --- |
| `attacking-eks-gke-aks` | A managed Kubernetes cluster: pod-to-cloud IMDS, IRSA/Workload Identity, k8s RBAC |
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
| `auditing-mcp-servers` | Reviewing an MCP server: tool-definition injection, per-tool authorization |

### Navigation

| Skill | Use it for |
| --- | --- |
| `mapping-attack-techniques` | Resolving an ATT&CK ID, tactic, or intel report to the skill that holds the procedure; purple-team loop and coverage reporting |

Techniques are indexed in [`secskills-core/ttp-index.json`](secskills-core/ttp-index.json)
(143 mapped, spanning all three plugins), which generates the `## ATT&CK
Coverage` section in each skill.
CI fails if a section drifts from the index, and skills that use a different
framework — ATLAS for AI, the Mobile matrix, CWE for code-level work — are
declared as such rather than counted as coverage.

## Examples

**Audit a codebase**

```
"Audit the authentication and billing code in this repo for vulnerabilities."
```

Builds a target model first, ranks entry points by reachability, traces the
top ones to their sinks, runs variant analysis on anything confirmed, and
reports coverage honestly — including what it did not reach.

**Review a pull request**

```
"Security review this branch before I merge it."
```

Diffs against the real merge base, triages hunks by exposure, reads the
removed lines for deleted checks, verifies findings against callers, and
separates blocking from non-blocking with a "reviewed but clear" section.

**Work an incident**

```
"A host is beaconing to an unfamiliar domain. Where do I start?"
```

Tells you what to preserve before anyone touches the box, then works scope
before containment — because partial containment warns the attacker.

**Reverse a cross-platform mobile app**

```
"jadx shows nothing useful in this APK and Burp sees no traffic."
```

Checks the framework markers first, recognizes Flutter, and explains that both
symptoms have the same cause — then routes to the blutter and reFlutter
workflow rather than guessing at obfuscation.

**Assess an AI feature**

```
"Review this RAG agent for prompt injection."
```

Maps whether the lethal trifecta closes — private data, untrusted content, and
egress in the same agent — before discussing any specific payload, and refuses
to accept prompt-level defenses as a control.

## Where this fits

SecSkills is domain expertise, not a scanner. It complements Anthropic's
first-party tooling rather than replacing it:

| Layer | Tool |
| --- | --- |
| While Claude writes code | [`security-guidance`](https://code.claude.com/docs/en/security-guidance) plugin — per-edit patterns and end-of-turn review |
| One-pass branch review | Built-in `/security-review` |
| Deep multi-agent scan | [`claude-security`](https://code.claude.com/docs/en/claude-security) plugin |
| On pull requests | Claude Code Review |
| **Domain methodology and judgment** | **SecSkills** |
| In CI | Your existing SAST and dependency scanners |

Run them together. The scanners find what they have rules for; the skills
supply the reasoning around them.

## Requirements

Claude Code, and the tools a given technique calls for (`nmap`, `semgrep`,
`volatility3`, `capa`, `ghidra`, …) installed separately. The plugin supplies
knowledge and method, not binaries.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the authoring standard. Before
opening a PR:

```bash
python3 scripts/validate.py --strict     # frontmatter, sections, manifests
python3 scripts/sync_attack.py --check    # ATT&CK sections match the index
python3 scripts/run_evals.py --check      # every skill has a trigger eval
```

CI runs the same three checks. Every new skill must ship with at least one
trigger-accuracy case in [`evals/cases.jsonl`](evals/README.md) — a realistic
user request labelled with the skill that should activate, plus a `trap_for`
case where it sits near an existing skill. This is how routing stays correct as
the collection grows. Contributions must serve authorized security work; no
working malware, implants, or evasion tooling.

## Legal

**For authorized use only.** Penetration testing with written permission,
in-scope bug bounty work, research on systems you control, education and CTFs,
and defensive operations.

Not for unauthorized access, illegal activity, or violating terms of service.
You are responsible for obtaining authorization and complying with applicable
law. Provided as-is, without warranty; the authors accept no liability for
misuse.

## License

MIT — see [LICENSE](LICENSE).

## Related work

Worth knowing about, and in several cases worth installing alongside this:

- [trailofbits/skills](https://github.com/trailofbits/skills) — 40+ skills for
  audit workflows, semgrep rule authoring, verification, and secure contracts
- [anthropics/claude-plugins-official](https://github.com/anthropics/claude-plugins-official)
  — the `security-guidance` and `claude-security` plugins
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/),
  [MITRE ATT&CK](https://attack.mitre.org/),
  [Sigma](https://github.com/SigmaHQ/sigma),
  [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
