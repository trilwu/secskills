---
name: auditing-supply-chain
description: Audit software supply chain risk — dependency and transitive package review, typosquatting and dependency confusion, lockfile and SBOM analysis, CI/CD pipeline and GitHub Actions security, build provenance, and secrets exposure. Use when assessing third-party package risk, reviewing a build pipeline, investigating a malicious package, or hardening release infrastructure.
---

# Auditing Supply Chain

Your build pipeline runs more untrusted code than your application does. A
single unpinned action, a postinstall script, or a workflow with a writable
token is a path from a stranger's commit to your production artifacts and
your signing keys.

## When to Use

- Assessing risk from third-party dependencies in an application
- Reviewing CI/CD pipelines, GitHub Actions, and release automation
- Investigating a suspicious or malicious package
- Producing or reviewing an SBOM
- Hardening build provenance and artifact signing
- Responding to a disclosed upstream compromise

## When NOT to Use

- **Vulnerabilities in first-party code** — use `auditing-code-for-vulnerabilities`
- **Model and dataset provenance** — use `securing-ai-systems`
- **Cloud infrastructure posture generally** — use `exploiting-cloud-platforms`
  for offensive assessment
- **An in-progress compromise** — use `responding-to-incidents`

## Two Different Risks

Keep them separate; they need different responses.

| | **Known-vulnerable dependency** | **Malicious dependency** |
| --- | --- | --- |
| Detection | CVE databases, `npm audit`, `osv-scanner` | Behavioural review, install scripts, publisher anomalies |
| Signal | Loud and well-tooled | Quiet; scanners usually miss it |
| Response | Patch, or justify the risk | Incident — assume credentials on the build host are burned |
| Time pressure | Days to weeks | Hours |

Most programs handle the first and are blind to the second. Give the second
explicit attention.

## Dependency Review

```bash
# Known vulnerabilities, ecosystem-agnostic
osv-scanner --lockfile=package-lock.json --lockfile=go.sum --lockfile=Cargo.lock
trivy fs --scanners vuln,secret,misconfig .
grype dir:.

# Ecosystem-native
npm audit --omit=dev && npm ls --all --depth=99 | wc -l   # count transitives
pip-audit -r requirements.txt
cargo audit
govulncheck ./...    # reachability-aware: only reports vulns you actually call
mvn dependency-check:check
```

`govulncheck`-style reachability analysis matters: a vulnerability in a code
path you never execute is a patching task, not a risk. Prioritize by
reachability plus exposure, not by CVSS alone.

**Transitive depth is the real surface.** Direct dependencies are chosen and
reviewed; transitive ones are inherited. Count them, and know which
maintainers you are implicitly trusting.

## Detecting Malicious Packages

Triage signals, roughly in order of how strongly they indicate malice:

| Signal | How to check |
| --- | --- |
| Install-time script execution | `postinstall`/`preinstall` in package.json; `setup.py` with network or exec calls; `build.rs` |
| Obfuscated or minified source in a non-minified package | Read the published tarball, not the repo — they differ |
| Network calls at import/require time | Static grep for HTTP/DNS in module top-level |
| Environment and credential access | Reads of `~/.aws`, `.npmrc`, `.git-credentials`, `process.env` dumps |
| New maintainer or a version published from a new account | Registry metadata, publish history |
| Name close to a popular package | Levenshtein distance against top-N package list |
| Published artifact ≠ repository source | Compare the tarball to the tagged commit |
| Version jump with no corresponding commits | Registry vs VCS history |

```bash
# Review what actually ships, not what the repo shows
npm pack <pkg> && tar -xzf <pkg>.tgz && rg -n 'child_process|eval\(|Buffer\.from\(.*base64|https?://' package/
pip download --no-deps --no-binary :all: <pkg> && tar -xzf <pkg>.tar.gz
rg -n 'os\.system|subprocess|urllib|requests|__import__|exec\(' <pkg>/setup.py

# Block install scripts by default in CI
npm ci --ignore-scripts
pip install --require-hashes -r requirements.txt
```

**Dependency confusion**: if an internal package name is not also registered
(or reserved) on the public registry, and the resolver can reach the public
registry, an attacker can publish a higher version and win resolution.

```bash
# Enumerate internal-looking names and check public availability
rg -o '"@?[a-z0-9-]+/[a-z0-9-]+"' package.json | sort -u
# Fix: scoped registries with strict scope→registry mapping, and
# `.npmrc` / `pip.conf` that never falls back to the public index for
# internal scopes
```

## Lockfiles and Pinning

- Lockfiles must be committed, reviewed in PRs, and CI must install **from**
  the lockfile (`npm ci`, `pip install --require-hashes`, `cargo --locked`,
  `go mod verify`) rather than resolving fresh.
- A lockfile diff in a PR that touches packages unrelated to the change is a
  review flag, not noise.
- Pin by integrity hash where the ecosystem supports it. Version pinning alone
  does not protect against a re-published version in registries that permit it.

## CI/CD Pipeline Security

This is where the highest-impact findings usually are.

### GitHub Actions

```bash
# Unpinned third-party actions — anyone who controls the tag controls your CI
rg -n 'uses:\s+(?!actions/)[^@]+@(?!v?[0-9a-f]{40})' .github/workflows/

# The dangerous trigger: pull_request_target runs with repo secrets and
# write-capable tokens, in the base repo context
rg -n 'pull_request_target|workflow_run' -A15 .github/workflows/

# Script injection: untrusted event data interpolated directly into a shell
rg -n '\$\{\{\s*github\.event\.(issue|pull_request|comment|head_commit)' .github/workflows/
```

Three findings to check for on every repository:

1. **`pull_request_target` + checkout of the PR head.** This executes a
   stranger's code with your secrets. It is a critical finding whenever the
   workflow also runs build or test steps from the checked-out tree.
2. **Untrusted interpolation into `run:`.** `${{ github.event.issue.title }}`
   inside a shell block is command injection with a public entry point. Pass
   through an `env:` variable and quote it instead.
3. **Over-broad `permissions`.** Default `GITHUB_TOKEN` scope should be
   `contents: read`, elevated per-job only where needed. Check for
   `permissions: write-all` and for the absence of any `permissions:` block.

Also review: self-hosted runners on public repos (persistent compromise, no
isolation between jobs), secrets available to fork-triggered workflows, cache
poisoning across branches, and artifact upload of build directories that
contain credentials.

### General pipeline

```bash
# Secrets in history, not just in the tree
gitleaks detect --source . --redact
trufflehog git file://. --only-verified

# IaC and container config
trivy config . && checkov -d .
hadolint Dockerfile
```

Check: who can trigger a deploy, whether deploy credentials are scoped per
environment, whether the build is reproducible, whether artifacts are signed,
and whether anyone can push directly to the release branch.

## SBOM and Provenance

```bash
# Generate — from the build, not from the source tree, so it reflects reality
syft dir:. -o cyclonedx-json=sbom.json
cdxgen -o sbom.json

# Consume — an SBOM is only useful if you scan it on a schedule
grype sbom:sbom.json
osv-scanner --sbom=sbom.json
```

An SBOM produced once for a compliance checkbox has no security value. The
value is in re-scanning existing SBOMs when a new vulnerability lands, which
answers "are we affected" in minutes instead of days.

**Provenance** (SLSA framing): can you prove which source commit produced a
given artifact, on which builder, with which dependencies? Sign artifacts
(`cosign`), record attestations, and verify signatures at deploy time. An
unverified signature is decoration.

```bash
cosign sign --key <key> <image>
cosign verify --key <pub> <image>
cosign verify-attestation --type slsaprovenance <image>
```

## Responding to an Upstream Compromise

```
1. Determine exposure: did any build pull the affected version? Check
   lockfiles across branches AND build logs — the lockfile shows intent, the
   build log shows what was actually installed.
2. Assume credential compromise on any host that ran the package's install
   scripts. Rotate: registry tokens, cloud keys, signing keys, SSH keys.
3. Preserve build logs and runner images before they roll off.
4. Check outbound network from build hosts for the exfil window.
5. Pin and rebuild; verify the rebuilt artifact differs only as expected.
6. Only then publish an advisory.
```

Rotation is not optional because the package "only ran in CI." CI is where the
production credentials live.

## Rationalizations to Reject

- *"It's a dev dependency."* Dev dependencies run on developer laptops and
  build servers with full credentials. That is a worse target than production.
- *"It has 10 million downloads a week, it must be safe."* Popularity is what
  makes it a target. Several of the largest incidents were top-100 packages.
- *"The scanner shows no CVEs."* Scanners find *known* vulnerabilities. A
  package that was malicious from its first publish has no CVE.
- *"We'll pin it later."* Unpinned actions and images are the standing risk;
  pinning takes minutes.
- *"The workflow is only triggered on PRs."* `pull_request_target` on PRs is
  exactly the dangerous case.
- *"It's an internal package name, no one knows it."* Package names leak
  through error messages, source maps, job logs, and public forks.
- *"We generated an SBOM."* Generating is not monitoring.

## Deliverable

- Dependency inventory with direct/transitive counts and maintainer
  concentration
- Known-vulnerability findings prioritized by reachability and exposure
- Malicious-package triage results with the signals checked
- Pipeline findings, with `pull_request_target`, unpinned actions, token
  scope, and injection sinks each explicitly stated as present or absent
- Secrets exposure (tree and history), with rotation status
- Provenance maturity: pinning, signing, attestation, verification-at-deploy
- Prioritized remediation, separating "patch" from "architectural"

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills-core/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Initial Access** (TA0001)

- [T1195](https://attack.mitre.org/techniques/T1195/) Supply Chain Compromise
- [T1195.001](https://attack.mitre.org/techniques/T1195/001/) Compromise Software Dependencies and Development Tools
- [T1195.002](https://attack.mitre.org/techniques/T1195/002/) Compromise Software Supply Chain

**Defense Evasion** (TA0005)

- [T1553](https://attack.mitre.org/techniques/T1553/) Subvert Trust Controls — see also `analyzing-malware`

**Credential Access** (TA0006)

- [T1552](https://attack.mitre.org/techniques/T1552/) Unsecured Credentials — see also `escalating-linux-privileges`, `exploiting-cloud-platforms`, `abusing-ci-cd-oidc`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## Reading External Sources

Fetch public advisories, specifications, and vendor reports as Markdown:

```bash
curl -sL "https://defuddle.md/<url>"      # scheme in the path is optional
```

This strips page boilerplate — roughly 78% fewer tokens on a prose page — and
returns the full text rather than a summary, so you can grep it and trust a
negative result.

Three things it is not for. Fetch JSON and API responses raw, because
readability extraction mangles structured data. Fetch authenticated or
JavaScript-rendered pages directly, because it retrieves them anonymously. And
never route **adversary infrastructure** (phishing links, C2, malware hosting),
**client-owned hosts**, or **engagement URLs** through it — the request leaves
your machine to a third party, and for live adversary infrastructure it also
tips off the operator.

Some sites block the extractor and return an error blob rather than the page —
`{"error":"Failed to fetch: 418 I'm a teapot"}` from freedesktop.org, for
instance. That is the fetch being refused, **not** the source saying the thing
does not exist. Re-fetch the URL directly before drawing any conclusion from
it.

## References

- `auditing-code-for-vulnerabilities` — first-party code review
- `securing-ai-systems` — model and dataset supply chain
- `responding-to-incidents` — handling a confirmed upstream compromise
- SLSA framework, OpenSSF Scorecard, CycloneDX/SPDX, Sigstore/cosign
- `osv-scanner`, `trivy`, `grype`, `syft`, `gitleaks`, `zizmor` (Actions auditing)
