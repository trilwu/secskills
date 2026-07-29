# Changelog

All notable changes to SecSkills are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [4.4.0] - 2026-07-28

A core methodology skill for running vulnerability discovery as an adversarial,
multi-agent loop rather than a single self-graded pass — translating the
"gauntlet loop" pattern (decompose, builder + independent critic, a bar the
agent can't rationalize around) into security research.

### Added

- **`orchestrating-vulnerability-research`** (core) — decompose a target
  (codebase, binary, or named live target) into independently-huntable slices,
  hunt each with a builder agent, and have a separate critic with fresh context
  refute every candidate against the real artifact (a reproduced crash, a
  working request, a proven bypass) before it counts. Dispatches
  `auditing-code-for-vulnerabilities`, `analyzing-binaries`, and
  `testing-web-applications` as per-slice hunters; hands proven findings to
  `reporting-security-findings`. Registered `_unmapped` (pre-attack research).

### Changed

- **`auditing-code-for-vulnerabilities`** — candidate-worklist discipline (grep
  hits are tracked candidates driven to an explicit verdict) and a revalidation
  pass that tries to kill each confirmed finding, including a git-history
  already-fixed check. Routing line added to the new orchestration skill.
- **`reporting-security-findings`** — require revalidation against what actually
  ships before filing a finding.

## [4.3.0] - 2026-07-27

Two PHP-focused core skills, split by intent as requested: hunting planted
malice versus auditing for vulnerabilities. Both shipped source-verified.

### Added

- **`hunting-web-backdoors`** (core) — find webshells and backdoors an attacker
  already planted in a web source tree: directory triage at scale, static
  deobfuscation with the never-execute-the-payload rule, append-infection
  detection by diff/checksum, known shell families as leads not verdicts, and
  the discipline that an empty `grep eval` is not a clean tree. Fills a real
  gap: `auditing-code-for-vulnerabilities` covers weaknesses, `analyzing-malware`
  covers a single recovered sample, but nothing swept a tree for planted code.
- **`auditing-php-applications`** (core) — the PHP-specific vulnerability layer
  on top of `auditing-code-for-vulnerabilities`: object injection via
  `unserialize` and `phar://` POP chains, type-juggling and magic-hash auth
  bypass, `php://`/`phar://` LFI-to-RCE wrappers, `extract()`/superglobal
  trust, SQLi, command sinks, and WordPress/Magento/Laravel context. Framed
  tightly as PHP-only and deferring general methodology to the parent skill, so
  it does not open per-language proliferation.

Both verified against php.net and RFCs before stamping — including the
version-gated traps the audit skill is built around: `preg_replace /e` removed
in 7.0, `create_function`/string-`assert` removed in 8.0, the PHP 8.0
number-vs-string comparison change (`0 == "foo"` true→false) while the `0e`
magic-hash bypass survives, `strcmp(array)` NULL→TypeError at 8.0, and the
`phar://` auto-unserialize removal in 8.0 (so that vector is a PHP 7.x issue).
Registered under `_unmapped`, made reachable from
`auditing-code-for-vulnerabilities` and `analyzing-malware`, with four
`trap_for` eval cases. Core: 20 → 22 (81 total).

## [4.2.0] - 2026-07-27

Four defense skills closing the offense/defense asymmetry surfaced by the gap
analysis: offensive skills existed for Kubernetes, containers, and cloud with
no defensive counterpart, cloud IR covered AWS and Azure but not GCP, and the
defense plugin was entirely reactive (DFIR, hunting) with no proactive posture
or vulnerability-management work. All four shipped source-verified.

### Added

- **`investigating-gcp-incidents`** (defense) — completes the cloud-IR trio.
  Leads with GCP's audit-log defaults because they decide the investigation:
  Admin Activity and System Event are always on (400-day `_Required` bucket),
  Data Access is off by default except BigQuery, so read/exfiltration activity
  is usually unprovable unless logging was enabled in advance — reported as a
  visibility gap, not "no exfiltration."
- **`defending-kubernetes`** (defense) — the blue-team counterpart to
  `attacking-eks-gke-aks` and `exploiting-containers`. RBAC capability
  enumeration (not role names), Pod Security Admission (`restricted`, since
  PSP was removed in 1.25), network-policy default-deny with CNI-enforcement
  caveat, token/secret exposure, control-plane and kubelet exposure, and
  turning on the audit log.
- **`hardening-cloud-posture`** (defense) — proactive counterpart to
  `exploiting-cloud-platforms`. Ranks by attack path over finding count
  (identity is the perimeter), reads CSPM output critically, and prefers
  org-level guardrails over point-fixes.
- **`managing-vulnerabilities`** (defense) — risk-based prioritization: CVSS is
  severity not priority; combine with CISA KEV (confirmed exploited) and EPSS
  (30-day probability), reachability, and asset value; decide with SSVC
  (track/track*/attend/act); track fixes and exceptions honestly.

All four registered under `_unmapped` in `ttp-index.json` (cloud-IR and
defensive-process skills, none an Enterprise ATT&CK technique), made reachable
from their offensive and sibling skills, and covered by new `trap_for` eval
cases. Verified against primary sources before stamping: GCP audit-log
streams, defaults, retention, method names and IAM permissions; Kubernetes PSP
removal (1.25) and Pod Security levels; EPSS/KEV/SSVC definitions and outcomes.
Plugin counts: offense 37, defense 22, core 20 (79 total).

## [4.1.0] - 2026-07-27

Three new skills filling gaps identified by surveying comparable projects
(Trail of Bits' skills, awesome-dfir-skills) and the 2025-2026 research on
where LLM-driven security work fails. All three shipped source-verified.

### Added

- **`recognizing-deception`** (offense) — honeypots, canary tokens, decoy AD
  accounts, and deceptive cloud credentials, and how to handle a suspected
  decoy without tripping it. Addresses the documented failure mode where an
  agent's state is poisoned by an environment that deliberately lies to it:
  evidence grounding defends against self-generated hallucination but not
  against a convincing planted service. No comparable project covers this.
- **`maintaining-engagement-state`** (core) — the durable record that outlives
  a session: credential provenance, access inventory, an artifact register for
  cleanup, findings with evidence, and a dead-end log. Addresses LLM
  statelessness and short context across multi-day engagements, and makes
  findings attributable and cleanup possible.
- **`triaging-security-alerts`** (defense) — working an alert queue to a
  defensible disposition: the true / benign-true / false-positive distinction,
  base-rate reasoning before escalation, cheapest-discriminator enrichment
  order, and time-boxing. The single highest-volume SOC task, previously
  absent; the defense plugin held only post-incident and hunting skills.

Each is registered in `ttp-index.json` (all three under `_unmapped` — Engage,
process discipline, and defensive process respectively, none an Enterprise
ATT&CK technique), reachable from existing domain skills, and covered by new
`trap_for` eval cases. Plugin counts: offense 37, defense 18, core 20.

## [4.0.0] - 2026-07-26

Split the single `secskills` plugin into three, so users install only the side
they work.

### Changed

- **The collection is now three plugins in one marketplace:**
  - `secskills-offense` (36 skills) — exploitation and attacker tradecraft.
  - `secskills-defense` (17 skills) — DFIR, threat hunting, detection.
  - `secskills-core` (19 skills) — dual-use: reverse engineering, source-code
    and supply-chain auditing, cryptography and PR review, AI/LLM and MCP
    security, ATT&CK mapping, and reporting. The shared foundation both sides
    reference; ships `ttp-index.json`.
- Skills moved into `secskills-offense/`, `secskills-defense/`, and
  `secskills-core/`, each with its own `.claude-plugin/plugin.json`.
- `ttp-index.json` moved to `secskills-core/`; the `mapping-attack-techniques`
  skill and `sync_attack.py` reference the new path. The index still maps
  techniques to skills across all three plugins as one unit.
- `validate.py`, `sync_attack.py`, and `run_evals.py` discover skills across
  every `secskills-*/skills/` dir, so the ATT&CK index, evals, and
  cross-references keep working as a union. `validate.py` now checks each
  plugin's manifest, its marketplace listing, and its own skill count.
- Cross-plugin skill references degrade gracefully: a hand-off to a skill in a
  plugin the user did not install is an inert mention, not a broken link.

### Removed

- The single `secskills` plugin and the root `.claude-plugin/plugin.json`.
  **Breaking:** re-install as `secskills-offense`/`-defense`/`-core`.

## [3.0.0] - 2026-07-26

### Removed

- **The 10 custom subagents** (`code-auditor`, `dfir-analyst`, `malware-analyst`,
  `detection-engineer`, `pentester`, `cloud-pentester`, `mobile-pentester`,
  `recon-specialist`, `red-team-operator`, `web3-auditor`) and the `agents`
  array in `plugin.json`. They largely mirrored the skill domains 1:1 and mostly
  delegated methodology back to the skills; with the main loop able to invoke
  skills directly and spawn subagents on demand, the static roster was redundant
  surface. The knowledge lives in the 72 skills. This is a breaking change for
  anyone invoking those agents by name, hence the major version bump.

### Changed

- `validate.py` no longer checks an `agents/` directory; README, CONTRIBUTING,
  and both manifests drop the subagent references.

## [2.11.1] - 2026-07-26

Source-grounding and adversarial fact-check pass over the 12 skills added in
2.9.0–2.11.0. Each was verified against primary sources (IETF RFCs, MITRE
ATT&CK, official tool docs, AWS/Microsoft/Azure docs) by one agent, then
re-checked by an independent adversarial reviewer instructed to assume an error
remained. **31 factual corrections applied across 11 of the 12 skills; only
`attacking-oauth-oidc` was clean under both passes.** No fabricated concepts or
dangerously-wrong techniques were found — every fix was in a *specific* (a flag,
an identifier, a field name, a variant label, or an internally-impossible
example).

### Fixed

- `attacking-jwt` — psychic-signature flag `-X b`→`-X p`; RSA n-recovery uses
  `jwt_forgery.py` (not two tokens to `-X k`); `jwx` RSA keygen `--keysize`;
  tamper-and-sign needs `-I` (without it `-pc/-pv` are ignored, so `role=admin`
  was never set).
- `analyzing-shellcode` — ror13 harness computed function-name-only hash
  (matches no real shellcode); now `ror13(module UTF-16LE upper) + ror13(func)`
  reproducing the canonical `LoadLibraryA=0x0726774C`; `speakeasy --raw --arch`;
  scdbg dump line.
- `attacking-saml` — XSW4 is nesting not sibling; XSW7 wraps the copied
  assertion in `<Extensions>`, only XSW8 buries the original in `<Object>`.
- `writing-yara-rules` — xor 255→256 variants; `private`-string semantics;
  process scan takes the PID as final arg (not `-p`); `-s`/`-S` flags; `-w`
  suppresses (not emits) warnings.
- `investigating-aws-incidents` — `WebIdentity`→`WebIdentityUser`; `FederatedUser`
  is the `GetFederationToken` broker type, not SAML/OIDC; `PassRole` removed from
  the event-lookup list (it is a permission).
- `investigating-azure-incidents` — `KeyVaultData` is not a real table →
  `AZKVAuditLogs`.
- `analyzing-phishing-emails` — `Authentication-Results` example was impossible
  under RFC 7489 (aligned SPF/DKIM pass forces `dmarc=pass`); tool
  misattributions (`msgconvert`, `oledump.py`).
- `analyzing-network-traffic` — invalid Zeek `Community::pluginload` →
  `community-id-logging` script; RITA v5 CLI; `editcap -s` for payload trim.
- `analyzing-disk-images` — `ewfacquire -C` case number; `$MFT` is inode 0;
  NTFS mount `noload`→`norecover` (`noload` is ext-only).
- `exploiting-xxe` — local-DTD reuse entity/path mismatch; Azure/GCP IMDS need
  request headers a bare XXE GET cannot set (was a self-contradiction).
- `investigating-windows-endpoints` — event 4778 is session *reconnect*, not
  connect.

## [2.11.0] - 2026-07-26

Host and SOC forensics batch: endpoint DFIR, disk imaging, email, and Azure IR.

### Added

- `investigating-windows-endpoints` — Windows host DFIR cross-referencing
  independent artifacts into one timeline: execution evidence (Prefetch,
  Amcache, Shimcache, SRUM, UserAssist), the event-log workhorses by ID
  (Security/Sysmon/PowerShell/RDP/WMI), persistence and lateral-movement
  traces, `$MFT`/USN/`$LogFile` file-system forensics, and super-timelining
  with Chainsaw/Hayabusa/Plaso. Parallels `analyzing-linux-persistence`.
- `analyzing-disk-images` — dead-disk forensics from a verified read-only
  copy: acquisition/integrity, Sleuth Kit `fls`/`icat`/`tsk_recover`, Plaso
  super-timelines, carving with `photorec`/`bulk_extractor`, and offline hive
  mining. Parallels `analyzing-memory-images`.
- `analyzing-phishing-emails` — email forensics that checks each claim against
  unforgeable evidence: the Received chain, SPF/DKIM/DMARC alignment,
  lookalike/BEC detection, SafeLinks/URLDefense and QR (quishing) unwrapping,
  and attachment triage handed off to `analyzing-malware`.
- `investigating-azure-incidents` — Azure resource/subscription IR anchored on
  the calling identity: Activity Log KQL, role-assignment and service-principal
  abuse, managed-identity/IMDS theft, Defender for Cloud triage, data-theft and
  anti-forensics detection, cross-correlated to Entra. Completes the AWS / Azure
  / M365-Entra cloud-IR trio.

### Changed

- Routing added across `analyzing-linux-persistence`, `analyzing-memory-images`,
  `performing-social-engineering`, `investigating-m365-entra`, and
  `investigating-aws-incidents`.
- ATT&CK index: `analyzing-phishing-emails` mapped to T1566/T1566.001/T1566.002
  and T1598; the three investigation/analysis skills declared `_unmapped`
  consistent with their siblings.
- `evals/cases.jsonl` grew to 147 trigger-accuracy cases covering all 72 skills.

## [2.10.0] - 2026-07-26

Defensive depth batch: cloud IR, network forensics, and detection/RE artifacts.

### Added

- `investigating-aws-incidents` — AWS cloud-log DFIR anchored on the compromised
  principal: CloudTrail `userIdentity`/`sessionContext` triage, IAM-persistence
  and IMDS-credential-theft signatures, GuardDuty finding triage, anti-forensics
  (StopLogging/DeleteTrail) defeated by the Organizations trail, and
  deactivate-not-delete containment. Parallels `investigating-m365-entra`.
- `analyzing-network-traffic` — PCAP/network forensics: Zeek and Suricata over a
  capture, `tshark` field extraction, beacon detection, DNS tunneling and DGA,
  JA3/JA4 and TLS fingerprinting, HTTP/file carving, and exfil hunting.
- `analyzing-shellcode` — raw position-independent code: emulation with
  scdbg/speakeasy, disassembly at the right base, decoder-stub unrolling
  (shikata_ga_nai), PEB-walk/API-hash resolution, and stage/family ID.
- `writing-yara-rules` — detection authoring for files and memory: string/hex
  modifiers, durable conditions, the PE/ELF/math modules, the
  specificity-vs-durability tradeoff, and goodware-corpus FP testing. Parallels
  `writing-sigma-rules`.

### Changed

- Routing added across `responding-to-incidents`, `analyzing-malware`,
  `analyzing-binaries`, `engineering-detections`, `hunting-threats`, and
  `writing-sigma-rules`.
- ATT&CK index: `analyzing-shellcode` mapped to T1027/T1140/T1620;
  `analyzing-network-traffic` mapped to T1071/T1071.004/T1573/T1568/T1132/T1048;
  `writing-yara-rules` and `investigating-aws-incidents` declared `_unmapped`
  (authoring/investigation methods, consistent with their siblings).
- `evals/cases.jsonl` grew to 139 trigger-accuracy cases covering all 68 skills.

## [2.9.0] - 2026-07-26

Procedure-skill batch: web authentication and federation depth.

### Added

- `attacking-jwt` — a JWT is a signature-verification decision the server makes
  on attacker-supplied bytes: `alg:none`, RS256→HS256 key confusion (with all
  three public-key acquisition routes), weak-secret cracking, `jku`/`x5u`/`kid`
  header injection, embedded-`jwk` self-signing, and the ES256 psychic-signature
  bug.
- `attacking-oauth-oidc` — the flow is the attack surface: `redirect_uri`
  validation bypasses, `state` CSRF, PKCE downgrade, code injection/replay,
  scope and consent abuse, `id_token` validation flaws, and "Sign in with X"
  account takeover.
- `attacking-saml` — XML Signature Wrapping (XSW1–XSW8) with SAML Raider,
  signature stripping, NameID comment injection, assertion replay, and Golden
  SAML.
- `exploiting-xxe` — in-band file read, `php://filter`, SSRF-to-metadata, blind
  out-of-band exfiltration via external DTD, XInclude without a DOCTYPE, and
  SVG/OOXML document XXE.

### Changed

- `testing-web-applications` and `testing-apis` route to all four.
- ATT&CK index gained T1606 (Forge Web Credentials) and T1606.002 (SAML Tokens),
  extended T1190 to `exploiting-xxe`, and T1528 to `attacking-oauth-oidc`.
- `evals/cases.jsonl` grew to 131 trigger-accuracy cases covering all 64 skills.

## [2.8.0] - 2026-07-26

Standards pass: aligns the collection with Anthropic's Agent Skills authoring
guidance and adds the one content gap a survey of the field surfaced.

### Added

- `producing-threat-intelligence` — CTI tradecraft: the intelligence lifecycle
  (and its two usual failures, skipping direction and skipping dissemination),
  passive-first indicator pivoting, the Diamond Model and Pyramid of Pain,
  attribution discipline (clustering vs naming, analytic confidence, ACH, bias
  traps), STIX/MISP/OpenCTI/TLP, and producing a finished product with a BLUF
  and a recommended action. Routed from `hunting-threats` and `analyzing-malware`.

### Changed

- Progressive disclosure: the 10 legacy skills that exceeded Anthropic's 500-line
  SKILL.md guideline (`testing-apis`, `exploiting-cloud-platforms`,
  `transferring-files`, `exploiting-web3-smart-contracts`,
  `performing-reconnaissance`, `establishing-persistence`,
  `escalating-windows-privileges`, `escalating-linux-privileges`,
  `enumerating-network-services`, `cracking-passwords`) now move their deepest
  command/payload catalogs into one-level-deep `references/` files, each with a
  table of contents. All 60 skills are now under 500 lines; no content was lost.
- `evals/cases.jsonl` grew to 123 trigger-accuracy cases covering all 60 skills.

## [2.7.0] - 2026-07-26

Procedure-skill batches 4-7: Active Directory/identity, cloud/container,
DFIR/detection, and specialist depth. Fifteen new procedure skills, taking the
collection to 59 skills. Each triggers on a specific artifact, tool, or symptom
and hands back to its domain skill.

### Added — Active Directory and identity depth

- `abusing-adcs` — AD Certificate Services abuse across ESC1-ESC16, template
  and CA misconfiguration, NTLM relay to web enrollment, certificate
  persistence that survives password resets, and the strong-mapping
  enforcement level that gates ESC9/ESC10/Certifried.
- `attacking-kerberos-delegation` — unconstrained delegation with printer-bug
  coercion, constrained delegation and the rewritable-service-class trick, and
  RBCD via machine-account creation as the highest-frequency delegation attack.
- `attacking-entra-id` — Entra ID recon, lockout-safe spraying, PRT and refresh
  token theft, application/service-principal consent abuse, Conditional Access
  bypass, cross-tenant guest pivoting, and hybrid-identity (PTA/sync) attacks.

### Added — cloud and container depth

- `attacking-eks-gke-aks` — the seam between cloud IAM and k8s RBAC: pod-to-cloud
  IMDS on EKS (IMDSv1/v2 hop limit), GKE Workload Identity, AKS pod identity,
  IRSA/OIDC trust abuse, and node-compromise paths.
- `attacking-serverless` — the event as the input surface, execution-role abuse
  as the real target, environment-variable credential theft, `/tmp` and layer
  persistence, and function-URL/authorizer misconfiguration.
- `abusing-ci-cd-oidc` — poisoned workflows, OIDC federation with over-broad
  subject claims turning a repo write into cloud credentials, self-hosted runner
  compromise, and secret exfiltration from pipeline runs.
- `escaping-hardened-containers` — what remains when `--privileged` is absent:
  single-capability escapes, seccomp-profile analysis, cgroup and filesystem
  paths, runc CVEs (Leaky Vessels), and gVisor/Kata sandbox limits.

### Added — DFIR and detection depth

- `analyzing-memory-images` — Volatility 3 workflow for injected code, in-memory
  credentials, dead-process network connections, and rootkit/DKOM detection that
  disk forensics cannot see.
- `investigating-m365-entra` — cloud-only DFIR where the only evidence is the
  Unified Audit Log, sign-in logs, and OAuth grants — including which logs exist,
  which need E5, and how long they last.
- `analyzing-linux-persistence` — the systematic sweep across every init path
  (systemd, cron, shell rc, SSH, kernel modules, LD_PRELOAD, package hooks, udev)
  because the attacker needs only the one you miss.
- `writing-sigma-rules` — Sigma field taxonomy, the selection/filter pattern,
  modifiers, backend conversion with pySigma, and specificity without brittleness.

### Added — specialist

- `testing-ics-ot-protocols` — safety-first testing of Modbus, DNP3, S7comm,
  OPC UA, and BACnet, where active scanning can crash a PLC and exploitation has
  physical consequences.
- `analyzing-firmware-images` — extraction with `binwalk`, filesystem carving,
  cross-architecture disassembly and emulation, and the hardcoded-credentials /
  CGI-command-injection / unsigned-update baseline.
- `attacking-bluetooth-nfc` — BLE GATT enumeration and plaintext-characteristic
  reads, MIFARE Classic (Crypto1) cloning, relay attacks, and RF sniffing.
- `auditing-mcp-servers` — the MCP server as a privilege boundary where every
  tool parameter is an indirect-injection surface, with tool-definition review,
  per-tool authorization, and transport security.

### Changed

- `attacking-active-directory`, `exploiting-cloud-platforms`,
  `exploiting-containers`, `responding-to-incidents`, `engineering-detections`,
  `securing-ai-systems`, `analyzing-binaries`, `attacking-wireless-networks`,
  and `enumerating-network-services` gained routing tables to the new depth
  skills, so each is reachable from its domain skill.
- ATT&CK index: seven of the new offensive skills map to Enterprise techniques
  (added T1648 Serverless Execution; extended T1078.004, T1199, T1528, T1552,
  T1552.005, T1558, T1610, T1611, T1649). The eight DFIR/detection/specialist
  procedure skills are declared unmapped with the framework that fits (ICS
  matrix, ATLAS, or "analysis method, not a technique").

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
