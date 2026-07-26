# SecSkills

**Security skills and subagents for [Claude Code](https://claude.com/claude-code) — 27 skills and 10 specialized subagents covering both halves of security work: finding and exploiting weaknesses, and finding and fixing them in code.**

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

Skills load only when relevant, so the reference material costs nothing until
it is needed.

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
python3 scripts/validate.py --strict
```

CI runs the same check. Contributions must serve authorized security work; no
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
