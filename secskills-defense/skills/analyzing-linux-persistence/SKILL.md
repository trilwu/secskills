---
name: analyzing-linux-persistence
description: Systematically identify and analyze persistence mechanisms on Linux systems during DFIR investigations -- sweep systemd units, cron jobs, shell initialization, SSH config, kernel modules, LD_PRELOAD, package manager hooks, udev rules, container entrypoints, and XDG autostart entries. Use when investigating a compromised Linux host, performing forensic analysis of a Linux disk image, looking for backdoors or unauthorized access mechanisms, or determining how an attacker maintained access.
verified: 2026-07-27
---

# Analyzing Linux Persistence

Linux persistence mechanisms are spread across dozens of locations that no
single tool checks comprehensively. The attacker needs only one you miss. The
work is a systematic sweep of every initialization path the kernel and
userspace honor, in a sequence that catches the common before the exotic.

## When to Use

- Investigating a compromised Linux host to find how the attacker kept access
- Forensic analysis of a Linux disk image or live system
- Looking for backdoors, unauthorized services, or rogue scheduled tasks
- Determining the full scope of attacker modifications during IR
- Validating that eradication removed every persistence mechanism

## When NOT to Use

- **Running a full incident response** -- use `responding-to-incidents`
- **Establishing persistence offensively** -- use `establishing-persistence`
- **Actively escalating privileges** -- use `escalating-linux-privileges`
- **The host is Windows** -- use `investigating-windows-endpoints`
- **You have an acquired disk image, not a live host** -- use `analyzing-disk-images`
- **Analyzing a recovered malware sample** -- use `analyzing-malware`

## Systemd Units

Systemd is the most common persistence vector on modern Linux. Check every
search path, not just `/etc/systemd/system`.

**Search paths (evaluated in priority order):**

```
/etc/systemd/system/          # admin-installed, highest priority
/run/systemd/system/          # runtime units, survive until reboot
/usr/lib/systemd/system/      # package-installed defaults
/usr/local/lib/systemd/system/
~/.config/systemd/user/       # per-user units (no root needed)
```

**Enumeration:**

```bash
# All enabled units -- compare against a known-good baseline
systemctl list-unit-files --state=enabled --type=service
systemctl list-unit-files --state=enabled --type=timer

# Recently modified service files
find /etc/systemd /run/systemd /usr/lib/systemd ~/.config/systemd \
  -name '*.service' -o -name '*.timer' -o -name '*.socket' \
  2>/dev/null | xargs ls -lt | head -30

# Show the full contents of a suspect unit
systemctl cat suspicious.service

# Check for drop-in overrides that modify legitimate units
find /etc/systemd/system/*.d /run/systemd/system/*.d \
  -name '*.conf' 2>/dev/null

# Masked units -- attacker may mask a security service
systemctl list-unit-files --state=masked

# Systemd generators -- scripts that dynamically create units at boot.
# Four directories, in ascending precedence. Checking only the first two
# misses generators dropped in the others.
ls -la /etc/systemd/system-generators/
ls -la /run/systemd/system-generators/         # tmpfs: runtime-injected
ls -la /usr/local/lib/systemd/system-generators/
ls -la /usr/lib/systemd/system-generators/
```

A generator under `/run` does not survive reboot, so it is not persistence in
the strict sense — but it is a live execution primitive, and its absence from a
post-reboot image does not mean it was never there. Note it on a running host
before you collect.

**What to look for:** `ExecStart` pointing to `/tmp`, `/dev/shm`, or writable
paths. `Restart=always` units. Timers with unusual schedules. Drop-ins that
change `ExecStart` on legitimate services. Generators not from any package.

## Cron and At Jobs

```bash
# System crontab
cat /etc/crontab

# System cron directories
ls -la /etc/cron.d/
ls -la /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/

# Per-user crontabs -- enumerate every user
for user in $(cut -d: -f1 /etc/passwd); do
  echo "=== $user ==="; crontab -l -u "$user" 2>/dev/null
done

# Anacron
cat /etc/anacrontab

# At queue -- one-shot scheduled commands
atq
for job in $(atq | awk '{print $1}'); do at -c "$job"; done

# Systemd timers (modern cron replacement)
systemctl list-timers --all

# Recently modified cron files
find /etc/cron* /var/spool/cron -type f -newer /etc/hostname 2>/dev/null
```

**What to look for:** Entries appended to existing files. Jobs running as root
from unusual paths. Cron scripts with modification times not matching package
install dates. One-shot `at` jobs that download and execute.

## Shell Initialization Files

```bash
# System-wide
cat /etc/profile
ls -la /etc/profile.d/
cat /etc/bash.bashrc          # Debian/Ubuntu
cat /etc/bashrc               # RHEL/CentOS
cat /etc/environment
ls -la /etc/environment.d/

# Per-user -- check every user with a login shell
for home in $(awk -F: '$7 !~ /(nologin|false)/ {print $6}' /etc/passwd); do
  echo "=== $home ==="
  for f in .bashrc .bash_profile .bash_login .profile .zshrc .zprofile \
           .zlogin .zshenv .config/fish/config.fish; do
    [ -f "$home/$f" ] && echo "--- $f ---" && tail -5 "$home/$f"
  done
done

# Check for sourced external files
grep -rn 'source \|^\. ' /etc/profile.d/ /root/.bashrc /root/.profile 2>/dev/null
```

**What to look for:** Lines appended to rc files that launch background
processes or modify PATH. Sourced files in unusual locations. Environment
variables setting `LD_PRELOAD`, `LD_LIBRARY_PATH`, or prepending attacker
directories to `PATH`.

## SSH Persistence

```bash
# Authorized keys -- check every user
find / -name authorized_keys -o -name authorized_keys2 2>/dev/null | \
  while read f; do echo "=== $f ==="; cat "$f"; done

# Look for command= and from= restrictions (or lack thereof)
grep -n 'command=\|from=\|environment=\|no-pty\|permitopen' \
  /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null

# SSH daemon configuration
sshd -T 2>/dev/null | grep -iE 'permit|auth|allow|forcecommand|match'
diff /etc/ssh/sshd_config /etc/ssh/sshd_config.dpkg-dist 2>/dev/null

# Config drop-ins
ls -la /etc/ssh/sshd_config.d/ 2>/dev/null

# PAM configuration for SSH
cat /etc/pam.d/sshd
# Look for added auth sufficient lines or custom PAM modules
# PAM module locations are distro-specific. Debian/Ubuntu use a multiarch
# path, so the RHEL-style list alone returns nothing there -- and an empty
# result reads as "no rogue module" when you simply looked in the wrong place.
find /lib/security/ /lib64/security/ /usr/lib/security/ /usr/lib64/security/ \
     /lib/*-linux-gnu/security/ /usr/lib/*-linux-gnu/security/ \
  -name 'pam_*.so' 2>/dev/null | \
  xargs -I{} sh -c 'rpm -qf {} 2>/dev/null || dpkg -S {} 2>/dev/null || echo "UNOWNED: {}"'

# SSH agent hijacking -- check for forwarded agent sockets
find /tmp -name 'agent.*' -type s 2>/dev/null
grep -r SSH_AUTH_SOCK /proc/*/environ 2>/dev/null | tr '\0' '\n'

# SSH certificates
ls -la /etc/ssh/ssh_host_*cert* 2>/dev/null
cat /etc/ssh/sshd_config | grep -i trustedusercakeys
```

**What to look for:** Keys added to root or service accounts. `command=`
entries executing reverse shells or tunnels. `PermitRootLogin yes` or
`PasswordAuthentication yes` against policy. Custom PAM modules not from any
package. `ForceCommand` or `Match` blocks proxying access.

## Kernel-Level Persistence

```bash
# Loaded kernel modules
lsmod
# Details on each module -- look for unsigned or out-of-tree modules
for mod in $(lsmod | awk 'NR>1{print $1}'); do
  modinfo "$mod" 2>/dev/null | grep -E 'filename|description|author|sig'
done

# Modules configured to load at boot
cat /etc/modules
ls -la /etc/modules-load.d/
cat /etc/modprobe.d/*

# DKMS-built modules (may rebuild on kernel update)
dkms status 2>/dev/null

# eBPF programs -- increasingly used for rootkits
bpftool prog list 2>/dev/null
bpftool map list 2>/dev/null

# Check for modifications to the kernel command line
cat /proc/cmdline
```

**What to look for:** Modules not from any installed package or loaded from
writable directories. eBPF programs attached to kprobes or tracepoints. DKMS
modules that survive kernel upgrades. `init=` in the kernel command line
pointing to unexpected binaries.

## Package Manager Hooks

```bash
# APT hooks (Debian/Ubuntu)
ls -la /etc/apt/apt.conf.d/
grep -r 'Pre-Invoke\|Post-Invoke\|DPkg::Pre-Install\|DPkg::Post-Install' \
  /etc/apt/apt.conf.d/ 2>/dev/null

# dpkg triggers and post-install scripts
ls -la /var/lib/dpkg/info/*.postinst
# Check recently modified postinst scripts
find /var/lib/dpkg/info/ -name '*.postinst' -newer /var/log/dpkg.log \
  2>/dev/null

# YUM/DNF plugins (RHEL/CentOS/Fedora)
ls -la /etc/yum/pluginconf.d/ /etc/dnf/plugins/ 2>/dev/null
ls -la /usr/lib/yum-plugins/ /usr/lib/python*/site-packages/dnf-plugins/ \
  2>/dev/null

# RPM scriptlets
rpm -qa --scripts 2>/dev/null | grep -B2 -A5 'postinstall\|preinstall'

# Pacman hooks (Arch)
ls -la /etc/pacman.d/hooks/ /usr/share/libalpm/hooks/ 2>/dev/null
```

**What to look for:** Hooks executing binaries outside the package manager's
control. Post-install scripts modified after installation. Plugins not
corresponding to any installed package.

## LD_PRELOAD and Library Injection

```bash
cat /etc/ld.so.preload
grep -r LD_PRELOAD /etc/environment /etc/profile.d/ /etc/ld.so.conf.d/ \
  /etc/systemd/system/*.service 2>/dev/null

# Find libraries not owned by any package
ldconfig -p | awk '{print $NF}' | sort -u | \
  xargs -I{} sh -c 'dpkg -S "{}" 2>/dev/null || rpm -qf "{}" 2>/dev/null || echo "UNOWNED: {}"' | \
  grep UNOWNED

# Verify shared library integrity against package records
for lib in $(ldd /usr/sbin/sshd | awk '/=>/{print $3}'); do
  dpkg -V $(dpkg -S "$lib" 2>/dev/null | cut -d: -f1) 2>/dev/null || \
  rpm -V $(rpm -qf "$lib" 2>/dev/null) 2>/dev/null
done
```

**What to look for:** Any entry in `/etc/ld.so.preload` (almost never
legitimate). `LD_PRELOAD` in environment files or systemd `Environment=`
directives. Libraries not owned by any package or with checksums differing
from package manager records.

## Udev Rules and D-Bus Activation

```bash
# Udev rules -- trigger on hardware events
ls -la /etc/udev/rules.d/
ls -la /usr/lib/udev/rules.d/
grep -r 'RUN+=' /etc/udev/rules.d/ /run/udev/rules.d/ /usr/lib/udev/rules.d/ 2>/dev/null

# D-Bus system services
ls -la /etc/dbus-1/system.d/ /usr/share/dbus-1/system-services/ 2>/dev/null
# Look for services that auto-activate unexpected binaries
grep -r 'Exec=' /usr/share/dbus-1/system-services/ 2>/dev/null
```

**What to look for:** Udev rules with `RUN+=` that execute scripts on device
events (USB insertion is a common trigger). D-Bus service files that activate
binaries from unusual paths.

## Container-Specific Persistence

```bash
# Docker -- compare entrypoints against original images
docker inspect --format='{{.Config.Entrypoint}} {{.Config.Cmd}}' \
  $(docker ps -aq) 2>/dev/null
docker diff $(docker ps -q) 2>/dev/null
docker images --digests 2>/dev/null
cat /etc/docker/daemon.json 2>/dev/null

# Kubernetes -- mutating webhooks and unexpected sidecars
kubectl get mutatingwebhookconfigurations -o yaml 2>/dev/null
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: {range .spec.containers[*]}{.name} {end}{"\n"}{end}' 2>/dev/null
```

**What to look for:** Containers whose entrypoint differs from the original
image. `docker diff` showing added executables. Mutating webhooks injecting
sidecars. Images with no registry digest (locally built or tampered).

## XDG Autostart and Desktop Entries

```bash
# System-wide autostart
ls -la /etc/xdg/autostart/

# Per-user autostart
find /home/*/.config/autostart/ /root/.config/autostart/ \
  -name '*.desktop' 2>/dev/null

# Check Exec= lines in desktop files
grep -r 'Exec=' /etc/xdg/autostart/ /home/*/.config/autostart/ 2>/dev/null
```

**What to look for:** Desktop entries that execute scripts from writable
locations. Autostart entries added for service accounts that should never
have a desktop session.

## Comprehensive Sweep and Forensic Artifacts

```bash
# Timestamp-sorted inventory across all persistence paths
{
  find /etc/systemd/system /run/systemd/system -type f 2>/dev/null
  find /etc/cron* /var/spool/cron -type f 2>/dev/null
  find /etc/profile.d/ -type f 2>/dev/null
  find / -name authorized_keys 2>/dev/null
  echo /etc/ld.so.preload
  find /etc/udev/rules.d/ /etc/xdg/autostart/ /etc/apt/apt.conf.d/ \
    -type f 2>/dev/null
} | xargs ls -lt --time-style=full-iso 2>/dev/null | head -60

# Files modified in the last 30 days across persistence paths
find /etc/systemd /etc/cron* /var/spool/cron /etc/profile.d \
  /etc/ssh /etc/pam.d /etc/modules-load.d /etc/udev/rules.d \
  /etc/xdg/autostart -type f -mtime -30 2>/dev/null | sort

# Files not owned by any package
# Debian/Ubuntu:
find /etc/systemd/system /etc/cron.d /etc/profile.d \
  -type f 2>/dev/null | xargs dpkg -S 2>&1 | grep 'not found'
# RHEL/CentOS:
find /etc/systemd/system /etc/cron.d /etc/profile.d \
  -type f 2>/dev/null | xargs rpm -qf 2>&1 | grep 'not owned'

# Process tree and network listeners
ps auxwwf
ss -tlnp
```

Collect these logs for timeline correlation: `/var/log/auth.log` (or
`/var/log/secure`), `/var/log/syslog` (or `journalctl` export),
`/var/log/apt/history.log` (or `/var/log/yum.log`), `/var/log/cron`,
`/etc/passwd`, `/etc/shadow`, `/etc/group`. Build a filesystem timeline
with `fls` or `find -printf` for MAC times.

## Rationalizations to Reject

- *"We checked cron and systemd, that covers it."* Those are two of more than
  a dozen persistence paths. The sweep is not complete until every section
  above is checked.
- *"The file timestamps look old, so it is legitimate."* Timestamps are
  trivially modified with `touch`. Correlate with package manager records and
  log entries, not just `mtime`.
- *"The attacker only had user-level access, so we only need to check
  user-writable locations."* User-level persistence includes systemd user
  units, crontabs, rc files, authorized_keys, XDG autostart, and LD_PRELOAD
  via environment files.
- *"We ran an AV scan and it found nothing."* AV detects known malware, not
  persistence mechanisms that use legitimate system features. A cron job
  running `curl | bash` will not trigger a signature.
- *"The system was rebuilt, so persistence does not matter."* Without knowing
  how they persisted, you cannot confirm the rebuild closed the path.
- *"We only need to check the locations that our EDR monitors."* EDR coverage
  varies by product and configuration. The sweep is tool-independent.

## References

- `responding-to-incidents` -- broader IR methodology that this analysis feeds
- `establishing-persistence` -- offensive perspective on the same mechanisms
- `escalating-linux-privileges` -- privilege escalation vectors that often
  pair with persistence
- `engineering-detections` -- building detection rules for the mechanisms found
- `hunting-threats` -- proactive searching for persistence across a fleet
