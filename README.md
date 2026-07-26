# SecSkills

**Security skills and subagents for [Claude Code](https://claude.com/claude-code) — 60 skills and 10 specialized subagents covering both halves of security work: finding and exploiting weaknesses, and finding and fixing them in code.**

```bash
/plugin marketplace add trilwu/secskills
/plugin install secskills@secskills-marketplace
/reload-plugins
```

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
| `investigating-m365-entra` | A cloud-only compromise: UAL, sign-in logs, OAuth consent grants, mailbox rules |
| `analyzing-linux-persistence` | Finding how an attacker persisted on a Linux host across every init path |
| `writing-sigma-rules` | Authoring a portable Sigma rule: field taxonomy, modifiers, backend conversion |

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

Techniques are indexed in [`secskills/ttp-index.json`](secskills/ttp-index.json)
(141 mapped), which generates the `## ATT&CK Coverage` section in each skill.
CI fails if a section drifts from the index, and skills that use a different
framework — ATLAS for AI, the Mobile matrix, CWE for code-level work — are
declared as such rather than counted as coverage.

## Subagents

Subagents run multi-step work in their own context. Claude selects them
automatically, or you can name one.

| Agent | Role |
| --- | --- |
| `code-auditor` | Finds exploitable bugs in source and diffs; verifies before reporting |
| `dfir-analyst` | Answers "how far did they get" and "are they still here" |
| `malware-analyst` | Triages and reverses samples; produces detection content |
| `detection-engineer` | Writes and tunes detections; runs hypothesis-driven hunts |
| `pentester` | Web, network, and Active Directory testing |
| `cloud-pentester` | AWS, Azure, GCP assessment |
| `mobile-pentester` | Android and iOS testing |
| `recon-specialist` | OSINT and attack surface mapping |
| `red-team-operator` | Post-exploitation and persistence |
| `web3-auditor` | Smart contract auditing |

```
"Audit this repo for authorization bugs"            → code-auditor
"Something's wrong with this server, here's the log" → dfir-analyst
"What does this binary do?"                          → malware-analyst
"Turn this intel report into detections"             → detection-engineer
"Use the cloud-pentester on this AWS account"        → explicit invocation
```

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
