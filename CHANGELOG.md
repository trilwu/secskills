# Changelog

All notable changes to SecSkills are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-07-26

The plugin was offensive-only. This release adds the defensive and code-level
half — vulnerability research, reverse engineering, malware analysis, DFIR,
detection engineering — and raises the authoring standard across the board.

### Added

**Skills (11 new, 27 total)**

- `auditing-code-for-vulnerabilities` — threat-model-driven source audit:
  context building, attack surface mapping, bug-class hunting, variant
  analysis, and a four-question verification gate before anything is reported.
  Includes a per-language bug-class checklist reference.
- `reviewing-code-changes` — security review of a diff, branch, or PR, with
  triage by exposure, explicit attention to *removed* lines, and
  false-positive discipline.
- `analyzing-binaries` — reverse engineering: triage, static disassembly,
  decompiler navigation, dynamic instrumentation, firmware, and anti-analysis.
- `analyzing-malware` — containment-first sample analysis, sandboxed
  detonation, config and C2 extraction, IOC tiering, and YARA authoring.
- `responding-to-incidents` — DFIR: order of volatility, chain of custody,
  triage collection, host/cloud/identity artifact analysis, timelining,
  scoping, containment, and blameless postmortems.
- `engineering-detections` — Sigma, YARA, and Suricata authoring with
  mandatory false-positive analysis, emulation testing, honest ATT&CK
  coverage accounting, and detection-as-code layout.
- `hunting-threats` — hypothesis-driven hunting with stack counting and
  outlier analysis across Splunk, KQL, and ES|QL.
- `securing-ai-systems` — LLM and agentic security: the lethal trifecta,
  indirect prompt injection through real ingestion paths, tool authority and
  confused-deputy review, RAG tenant isolation, model supply chain, and MCP
  server review. Includes an AI test-case reference.
- `auditing-supply-chain` — dependency and transitive review, malicious
  package triage, dependency confusion, GitHub Actions and CI/CD security,
  SBOM, and provenance.
- `reviewing-cryptography` — crypto misuse review: AEAD, nonce/IV handling,
  key management, password storage, randomness, timing side channels,
  signature verification, and TLS.
- `reporting-security-findings` — finding anatomy, CVSS plus business impact,
  proof-of-concept scope, report structure, and coordinated disclosure.

**Agents (4 new, 10 total)**

- `code-auditor` — source and diff security auditing with verification gates
- `dfir-analyst` — incident response, forensics, and scoping
- `malware-analyst` — malware triage and reverse engineering
- `detection-engineer` — detection authoring, tuning, and threat hunting

**Repository quality**

- `scripts/validate.py` — dependency-free validator for plugin structure,
  skill and agent frontmatter, naming, required sections, referenced files,
  and manifest version agreement.
- `.github/workflows/validate.yml` — CI running the validator in `--strict`
  mode on every push and pull request, with pinned actions and read-only
  token permissions.
- `CONTRIBUTING.md` — authoring standard, required sections, and review bar.
- This changelog.

### Changed

- **Skill directories renamed to match their frontmatter `name`.** Previously
  every directory disagreed with the name that determines the command
  (`web-app-security/` declaring `testing-web-applications`), which made the
  repository hard to navigate and the commands unpredictable.
- **Every legacy skill gained a `## When NOT to Use` section** naming the
  correct alternative skill, so skills stop competing for the same requests.
- **Agents now use `model: inherit`** instead of pinning `sonnet`, so they run
  on the session's model.
- `plugin.json` gained `homepage`, `repository`, `license`, and `keywords`;
  `marketplace.json` gained `category`, `keywords`, `license`, and `homepage`.
- README rewritten around the offensive/defensive split and the new inventory.

### Migration

Existing installs pick this up with `/plugin update secskills`. Skills are
invoked by their frontmatter name, which did not change, so any workflow that
referenced a skill by name keeps working. Only the on-disk directory layout
changed.

## [1.0.0] - Initial release

- 16 offensive security skills covering web applications, APIs, Active
  Directory, Linux and Windows privilege escalation, network services,
  containers, cloud, mobile, wireless, passwords, persistence, file transfer,
  phishing, reconnaissance, and Web3.
- 6 subagents: `pentester`, `cloud-pentester`, `mobile-pentester`,
  `recon-specialist`, `red-team-operator`, `web3-auditor`.
- Claude Code plugin and marketplace manifests.
