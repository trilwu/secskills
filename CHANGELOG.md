# Changelog

All notable changes to SecSkills are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [2.6.0] - 2026-07-26

Procedure-skill batch 3: web and API depth.

### Added

- `exploiting-ssrf` — cloud metadata across AWS IMDSv1/v2, Azure, and GCP with
  a clear account of why IMDSv2 stops simple fetchers and not request proxies;
  the full bypass ladder including DNS rebinding and the redirect gap that is
  the default configuration of most HTTP libraries; blind confirmation and
  renderers that hand back readable responses.
- `exploiting-deserialization` — magic-byte identification across five
  runtimes, `URLDNS` before gadget guessing, PHP Phar as the vector with no
  visible `unserialize()`, .NET `TypeNameHandling`, and the queue/cache
  locations where serialized data reaches higher-privilege consumers.
- `attacking-graphql` — schema recovery when introspection is disabled,
  per-field and traversal authorization as the main event, alias and array
  batching defeating HTTP-layer rate limits, and proving DoS by gradient
  rather than by outage.
- `attacking-grpc-protobuf` — four schema-recovery routes, gRPC framing so a
  raw payload can be decoded, per-method authorization since path-based
  filtering does not apply, and metadata-as-identity bypasses.

### Changed

- `testing-apis` and `testing-web-applications` route to all four.
- ATT&CK index gained T1552.005 (Cloud Instance Metadata API) and extended
  T1190 to the four new skills — these map to the matrix, unlike the mobile
  and binary procedure skills.

## [2.5.0] - 2026-07-26

Procedure-skill batch 2: binary and language-runtime depth.

### Added

- `analyzing-go-binaries` — `pclntab` survives `strip`, so "stripped" Go is
  fully recoverable; plus `go version -m` as a free SBOM, the pre-1.17 stack
  calling convention that makes decompilers produce nonsense, and struct tags
  that hand you the wire protocol.
- `analyzing-dotnet-assemblies` — identify the obfuscator before fighting it,
  the seven obfuscation layers and their handling, and memory dumping as the
  general escape hatch for packed managed code.
- `analyzing-rust-binaries` — panic strings leak source paths and the crate
  dependency list before a single instruction is read; monomorphization,
  `Result`/`Option` returns, and vtable dispatch in the disassembler.
- `unpacking-protected-binaries` — the dynamic unpacking loop, OEP location
  signals, import repair as the step that actually fails, TLS callbacks
  running before the entry point, and treating virtualized functions as black
  boxes with observable I/O rather than a devirtualization project.

### Changed

- `analyzing-binaries` routes language runtimes and packed executables to the
  new skills.

## [2.4.0] - 2026-07-26

Procedure-skill batch 1: the mobile cluster is now complete.

### Added

- `reversing-xamarin-maui` — the three Xamarin packaging generations
  (plain DLLs, XALZ-compressed, AssemblyStore blob) and why Frida's Java
  bridge cannot see Mono methods.
- `bypassing-root-jailbreak-detection` — separates the four detection layers,
  leads with environment hiding over hooking, treats Frida detection as its own
  problem, and states plainly where hardware attestation cannot be hooked at
  all — with the advice to request an exemption rather than lose days to a TEE.
- `analyzing-ios-binaries` — FairPlay decryption as the gate everything else
  depends on, Mach-O load commands, entitlements, Objective-C recovery, and the
  realistic limits of static Swift analysis.
- `testing-mobile-ipc` — exported components, content provider SQLi and
  traversal, intent redirection, PendingIntent hijacking, App Links
  verification, iOS URL schemes and App Groups.

### Changed

- `testing-mobile-applications` routes to all four, plus Xamarin in the
  framework-identification table.

## [2.3.0] - 2026-07-26

### Added

- `bypassing-mobile-pinning` — diagnoses the six distinct causes of a failed
  mobile TLS interception before reaching for a bypass, then hooks by stack
  (OkHttp, Conscrypt, WebView, native BoringSSL, Xamarin, Unity, gRPC on
  Android; NSURLSession, TrustKit, AFNetworking, Alamofire on iOS). Leads with
  the case that is not pinning at all: Android 7+ does not trust user-installed
  CAs, so an app with no pinning code still fails interception.

### Changed

- `testing-mobile-applications` routes proxy failures to the new skill before
  the reader concludes the app pins.

## [2.2.0] - 2026-07-26

Adds the procedure-skill tier: narrow, tool-and-artifact scoped skills for
situations a domain skill cannot carry without bloating for everyone who is
not in that situation.

### Added

- `reversing-flutter-apps` — Flutter/Dart reversing with blutter, plus the
  two failure modes that waste the most time on Flutter targets: an empty dex
  (logic is in `libapp.so`) and an empty proxy (Flutter ignores the system
  proxy *and* the system CA store).
- `reversing-react-native-apps` — plain vs Hermes bundle identification,
  `hbctool`/`hermes-dec`/`hasmer` version compatibility, string-table
  shortcuts, and bridge hooking.
- `reversing-unity-il2cpp` — Mono vs IL2CPP identification, recombining
  `global-metadata.dat` with `libil2cpp.so`, symbol import into IDA/Ghidra,
  and dumping encrypted metadata from memory.
- CONTRIBUTING now documents the two-tier model: how to tell a domain skill
  from a procedure skill, and how to write a description that triggers on
  artifacts and tools rather than competing with a domain skill.

### Changed

- `testing-mobile-applications` opens with a framework-identification check
  and a routing table, so a generic mobile request reaches the right procedure
  skill instead of concluding the app is obfuscated.
- `analyzing-binaries` routes framework runtimes to the procedure skills.

## [2.1.0] - 2026-07-26

### Added

- `secskills/ttp-index.json` — 139 ATT&CK techniques mapped to the skills that
  cover them, with an explicit `_unmapped` block naming the framework used
  instead where ATT&CK Enterprise does not apply.
- `scripts/sync_attack.py` — generates the `## ATT&CK Coverage` section in each
  mapped skill from the index; `--check` fails CI when a section drifts.
- `mapping-attack-techniques` — router from a technique ID, tactic, APT group,
  or intel report to the skill holding the procedure, with the purple-team
  loop and three-state coverage reporting (tested / untested / no telemetry).

### Changed

- Eight skills had their `When to Use` section at the bottom of the file; it
  now sits with `When NOT to Use` at the top.
- Kernel and NFS privilege escalation moved to
  `escalating-linux-privileges/references/kernel-and-nfs.md`.

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
