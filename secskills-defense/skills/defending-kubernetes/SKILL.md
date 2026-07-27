---
name: defending-kubernetes
description: Harden and monitor a Kubernetes cluster against the attacks that actually happen — RBAC least privilege and escalation paths, Pod Security Admission enforcement, network policy default-deny, secrets and service-account token exposure, control-plane and kubelet exposure, and audit-log-based detection. Use when reviewing a cluster's security posture, responding to a suspected cluster compromise, deciding what to enforce and detect, or translating an attack path from attacking-eks-gke-aks into a defense.
verified: 2026-07-27
---

# Defending Kubernetes

Kubernetes is insecure in useful defaults, not in exotic bugs. The attacks that
land are RBAC that grants more than intended, pods that run privileged because
nothing stops them, a flat pod network, and mounted service-account tokens with
cluster-wide reach. Defense is mostly closing those, in priority order, and
being able to see when someone tries.

This is the counterpart to `attacking-eks-gke-aks` and `exploiting-containers`:
read those to know what the attacker does; use this to know what to enforce and
what to watch.

## When to Use

- Reviewing a cluster's security posture or an admission/RBAC configuration
- Responding to a suspected cluster compromise (post-triage)
- Deciding what to enforce (Pod Security, network policy) and what to detect
- Translating an offensive cluster finding into a concrete control
- Hardening the control plane, kubelet, or etcd exposure

## When NOT to Use

- **Attacking the cluster** — use `attacking-eks-gke-aks`
- **Container escape and runtime internals specifically** — use
  `exploiting-containers` / `escaping-hardened-containers` for the technique;
  return here for the control
- **The cloud IAM plane around the cluster** (IRSA, workload identity, node
  role) — that is `investigating-*-incidents` / `hardening-cloud-posture`; a
  GKE/EKS/AKS incident usually needs both planes
- **Whether an alert is an incident** — use `triaging-security-alerts`

## Enforce in Priority Order

Order matters — these are ranked by how often the gap is the actual entry path.

### 1. RBAC least privilege

The most common real weakness. Look for the bindings that are escalation
primitives regardless of how innocent they look:

```bash
# Who can create pods anywhere? (→ mount any secret, run as any SA)
kubectl auth can-i create pods --all-namespaces --as=system:serviceaccount:ns:sa

# Subjects bound to cluster-admin
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.roleRef.name=="cluster-admin") | .subjects'
```

The dangerous verbs are not just `*`. `create pods` lets a subject run a pod
as any service account in the namespace and mount any secret — effectively
namespace-admin. `escalate` and `bind` on roles let a subject grant themselves
more than they hold. `create` on `pods/exec`, and access to
`secrets`, `serviceaccounts/token`, and `nodes/proxy` are each escalation
paths. Enumerate what subjects *can do*, not what their role is named.

### 2. Pod Security Admission

PodSecurityPolicy was removed in Kubernetes **1.25**; the built-in replacement
is **Pod Security Admission**, which enforces the three Pod Security Standards
levels — `privileged`, `baseline`, `restricted` — per namespace via labels:

```yaml
# Namespace label: enforce the restricted profile, and warn/audit on violations
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```

`restricted` blocks the pod configurations that make escape and privilege
escalation easy: privileged containers, host namespaces (`hostPID`, `hostNetwork`,
`hostIPC`), host-path mounts, running as root, added capabilities. A cluster
with no enforced profile is one `securityContext.privileged: true` away from a
node takeover. If you need policy beyond the three levels (image provenance,
registry allow-lists), that is an external admission controller (Kyverno, OPA
Gatekeeper) — note it, do not pretend PSA covers it.

### 3. Network policy default-deny

By default every pod can reach every other pod. A default-deny ingress policy
per namespace, with explicit allows, is what stops a single compromised pod
from becoming lateral movement. Confirm the CNI actually enforces NetworkPolicy
— some configurations accept the objects and enforce nothing, which is worse
than none because it looks covered.

### 4. Service-account tokens and secrets

- `automountServiceAccountToken: false` on pods that do not call the API.
  A mounted token plus a permissive RBAC binding is the standard in-cluster
  pivot.
- Kubernetes Secrets are base64, not encrypted, in etcd unless
  encryption-at-rest is configured. Confirm it is.
- Look for tokens and cloud credentials passed as env vars — they leak into
  logs and crash dumps.

### 5. Control-plane and kubelet exposure

- The API server should not be internet-facing without authn/authz and,
  ideally, network restriction. Anonymous auth must be off.
- The kubelet read-only port (10255) and the authenticated port (10250) must
  not be reachable from workloads; `nodes/proxy` RBAC and an exposed 10250 are
  a direct route to command execution on nodes.
- etcd must require mutual TLS — etcd access is game-over, it holds every
  secret.

## Detection: Turn on the Audit Log

Most clusters run with no meaningful audit policy, so there is nothing to
investigate after the fact. A cluster without an audit policy configured is the
Kubernetes version of GCP Data Access logging being off — the activity is
simply not recorded.

High-value audit signals:

- `exec`, `attach`, and `port-forward` into pods — interactive access
- Secret `get`/`list` at scale, especially cluster-wide
- `create`/`update` on `clusterrolebindings` and `rolebindings`
- Pods created with `privileged`, host namespaces, or host-path mounts
- Anonymous or `system:unauthenticated` requests that succeed
- Service-account token creation via the `TokenRequest` API

On managed clusters the audit log ships to the cloud logging plane (GKE →
Cloud Audit Logs, EKS → CloudWatch, AKS → Azure Monitor), which is where the
investigation joins up with the `investigating-*-incidents` skills.

## Rationalizations to Reject

- *"The role isn't named admin, so it's fine."* Names are irrelevant.
  `create pods` or `secrets get` in a namespace is namespace-admin in effect.
  Enumerate capabilities, not titles.
- *"We enforce Pod Security, so containers are contained."* Only if the profile
  is `restricted` and actually enforced, not merely `warn`. A `baseline` or
  audit-only label stops almost none of the escape paths.
- *"NetworkPolicies are defined, so the network is segmented."* Only if the CNI
  enforces them. Verify enforcement, not the presence of the objects.
- *"Secrets are in etcd, so they're protected."* They are base64 unless
  encryption-at-rest is on. Anyone who can read etcd or `get secrets` has them.
- *"It's a managed cluster, the provider secures it."* The provider secures the
  control plane it runs; RBAC, Pod Security, network policy, and workload
  identity are yours. Shared responsibility does not include your bindings.
- *"No alerts fired."* Check whether an audit policy exists at all before
  reading silence as safety.

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

- `attacking-eks-gke-aks` — the attack paths these controls close
- `exploiting-containers`, `escaping-hardened-containers` — the escape
  techniques Pod Security aims to prevent
- `hardening-cloud-posture` — the cloud IAM plane around the cluster
- `engineering-detections` — turning the audit signals above into rules
- `investigating-aws-incidents` / `investigating-gcp-incidents` — where a
  managed-cluster audit trail leads
