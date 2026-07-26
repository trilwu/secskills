---
name: investigating-windows-endpoints
description: Investigate a compromised or suspicious Windows host from on-disk artifacts -- triage collection, evidence of execution (Prefetch, Amcache, Shimcache, SRUM, UserAssist, BAM), the event-log workhorses by ID (Security 4624/4688/4720/7045/1102, Sysmon, PowerShell 4104, RDP, WMI), persistence hunting across every autostart, lateral-movement traces, $MFT/USN filesystem forensics, anti-forensics detection, and building a super-timeline with the Eric Zimmerman suite, Chainsaw, Hayabusa, and Plaso. Use when triaging a compromised or suspicious Windows host, working through EVTX/Sysmon logs, reconstructing what executed on a Windows machine, hunting persistence and lateral-movement traces, or analyzing a KAPE/triage collection.
---

# Investigating Windows Endpoints

Windows records execution, persistence, and access in dozens of artifacts the
attacker rarely cleans completely. The event logs are only the surface -- the
registry, prefetch, amcache, and the file-system journals corroborate or
contradict them. The investigation is cross-referencing independent artifacts
into one timeline that no single cleared log can defeat.

## When to Use

- Triaging a compromised or suspicious Windows host, live or from an image
- Working through a KAPE, Velociraptor, or EDR triage collection
- Reconstructing what executed on a Windows machine and in what order
- Parsing EVTX / Sysmon / PowerShell logs to reconstruct attacker activity
- Hunting persistence and lateral-movement traces across the endpoint
- Detecting timestomping, log clears, and other on-host anti-forensics

## When NOT to Use

- **The host is Linux** -- use `analyzing-linux-persistence`
- **You need the overall IR process and multi-host coordination** -- use
  `responding-to-incidents`; come here when one Windows host is the focus
- **You have a RAM capture to work** -- use `analyzing-memory-images`; come
  here for the on-disk artifacts
- **The compromise is in cloud identity, not on the endpoint** -- use
  `investigating-m365-entra`
- **Proactive fleet-wide hunting with no specific host** -- use
  `hunting-threats`
- **You are the attacker on the host, not the responder** -- use
  `escalating-windows-privileges`

## Triage Collection First

Do not analyze the live disk in place. Collect a triage set, hash it, and work
on the copy. For most incidents a targeted triage collection answers the
question faster than a full image; image only the hosts that matter.

**Dead vs. live acquisition.** A powered-off host or a mounted disk image is a
dead acquisition -- consistent, but you lose running processes, network state,
and unflushed logs. A live host lets you capture volatile state (memory,
`netstat -anob`, `Get-NetTCPConnection`, `tasklist /svc`) but every action
mutates the disk; record what you touch. Capture memory first if the host is
live and "are they still here" is open, then hand it to `analyzing-memory-images`.

```cmd
:: KAPE targeted triage -- the fastest way to a defensible artifact set
kape.exe --tsource C: --target !SANS_Triage --tdest E:\out\host01 --vhdx host01
:: Broader coverage: registry hives, event logs, $MFT/$J, browser, prefetch
kape.exe --tsource C: --target KapeTriage,RegistryHives,EventLogs,FileSystem ^
  --tdest E:\out\host01

:: Then run the parsers (Modules) over what you collected
kape.exe --msource E:\out\host01 --mdest E:\out\host01\parsed ^
  --module !EZParser
```

Velociraptor (`Windows.KapeFiles.Targets`) collects the same set at fleet scale
over an agent. Whatever the tool, verify hashes before and after every copy.

**Key artifact directories** to make sure your collection contains:

```
C:\Windows\System32\winevt\Logs\          Event logs (.evtx)
C:\Windows\System32\config\               Registry hives: SYSTEM, SOFTWARE, SAM, SECURITY
C:\Users\<u>\NTUSER.DAT                    Per-user registry hive
C:\Users\<u>\AppData\Local\Microsoft\Windows\UsrClass.dat   Shellbags, COM
C:\Windows\Prefetch\                       *.pf execution evidence
C:\Windows\appcompat\Programs\Amcache.hve  Amcache
C:\Windows\System32\sru\SRUDB.dat          SRUM
C:\Windows\System32\Tasks\                 Scheduled task XML
C:\$MFT  C:\$Extend\$UsnJrnl  C:\$LogFile  Filesystem journals
C:\$Recycle.Bin\                           Deleted-file $I records
```

## Evidence of Execution

Multiple independent artifacts record that a binary ran. Cross-reference them --
agreement raises confidence, disagreement is itself a finding.

```cmd
:: Prefetch -- run count, first/last run, files/dirs the binary touched.
:: Absent on most Servers; disabled on SSD-only systems -- note that, don't assume.
PECmd.exe -d C:\Windows\Prefetch --csv E:\out\parsed -q

:: Amcache -- SHA-1 of executed/present binaries, compile times, driver load
AmcacheParser.exe -f C:\Windows\appcompat\Programs\Amcache.hve ^
  --csv E:\out\parsed -i

:: Shimcache / AppCompatCache (SYSTEM hive) -- path + last-modified; presence
:: means the file was seen, NOT necessarily executed. Order is roughly LRU.
AppCompatCacheParser.exe -f C:\Windows\System32\config\SYSTEM --csv E:\out\parsed

:: SRUM -- per-process bytes sent/received and CPU over 30-60 days.
:: Ties an executable to network volume even when netflow is gone.
SrumECmd.exe -f C:\Windows\System32\sru\SRUDB.dat ^
  -r C:\Windows\System32\config\SOFTWARE --csv E:\out\parsed
```

From the user (NTUSER.DAT / UsrClass.dat) hives, parse GUI-execution and
file-access evidence with `RECmd`:

```cmd
:: UserAssist (GUI program launches, run count, focus time),
:: BAM/DAM (background/desktop activity moderator: last-run per exe per SID),
:: RecentDocs, and RunMRU in one pass with the bundled batch file
RECmd.exe -d C:\Users --bn BatchExamples\UserActivity.reb --csv E:\out\parsed
```

- **Jump Lists** (`...\Recent\AutomaticDestinations\*.automaticDestinations-ms`)
  and **LNK files** (`...\Recent\*.lnk`) record opened files/apps with target
  path, volume serial, and MAC times -- parse with `JLECmd` and `LECmd`.
- **RecentDocs** and shellbags (below) show what folders and files were opened.

## The Event-Log Workhorses

Parse EVTX first with a triage engine (Chainsaw / Hayabusa, below), then pivot
into specific channels. The IDs that carry the most weight:

**Security** (`Security.evtx`):

- **4624** logon success -- decode Logon Type: **2** interactive, **3**
  network (SMB, shares, PtH), **10** RemoteInteractive (RDP), **9**
  NewCredentials (runas /netonly, often Overpass-the-Hash). Pivot on
  LogonId to correlate a session's activity.
- **4625** logon failure -- password spraying and brute force by source IP.
- **4672** special privileges assigned -- admin-equivalent logon; pair with
  4624 to flag privileged sessions.
- **4648** explicit-credential logon -- runas and lateral movement.
- **4688** process creation -- with command-line auditing enabled, the full
  command line and parent process. The single most valuable Security event.
- **4720/4722/4738** account created/enabled/changed; **4728/4732/4756**
  member added to a global/local/universal privileged group (Domain Admins,
  local Administrators) -- attacker account and group manipulation.
- **4698/4699/4702** scheduled task created/deleted/updated.
- **7045** (System log) new service installed; **7036** service state change --
  the PsExec and lateral-tooling signature.
- **1102** the audit log was cleared -- an anti-forensic act and itself an
  indicator; correlate the gap it leaves.

**Sysmon** (`Microsoft-Windows-Sysmon/Operational`), if deployed, is the
richest source:

- **1** process create (with hashes, command line, parent) -- **3** network
  connection -- **7** image/DLL load (unsigned DLLs, sideloading) -- **8**
  CreateRemoteThread (injection) -- **10** process access (LSASS handle =
  credential dumping) -- **11** file create -- **12/13/14** registry
  create/set/rename (autoruns) -- **15** file-stream create (Zone.Identifier,
  ADS) -- **22** DNS query -- **23/26** file delete.

**PowerShell**:

- **4104** script-block logging (`Microsoft-Windows-PowerShell/Operational`) --
  deobfuscated script content; hunt for `-enc`, `FromBase64String`,
  `DownloadString`, `IEX`, AMSI-bypass strings. **4103** module/pipeline
  logging. **400/800** in `Windows PowerShell.evtx` (engine start, version --
  a v2 downgrade is evasion).

**RDP / TerminalServices**:

- Security **4778/4779** session connect/disconnect. **1149** in
  `TerminalServices-RemoteConnectionManager` (auth succeeded -- user + source
  IP). **21/22/25** in `TerminalServices-LocalSessionManager` (logon,
  shell start, reconnect).

**WMI** (`Microsoft-Windows-WMI-Activity/Operational`): **5857** provider
loaded, **5858** operation error, **5859-5861** permanent event-subscription
registration -- WMI persistence.

**Task Scheduler** (`Microsoft-Windows-TaskScheduler/Operational`): **106**
task registered, **140** updated, **141** deleted, **200/201** action
executed/completed -- corroborates Security 4698.

## Persistence Hunting

Sweep every autostart, not the handful your tool checks by default. This is the
defensive mirror of `establishing-persistence` -- read that skill for how each
mechanism is planted, then hunt for the traces here.

- **Run keys** -- `...\Software\Microsoft\Windows\CurrentVersion\Run` and
  `RunOnce`, per SOFTWARE and each NTUSER.DAT; also `...\Policies\Explorer\Run`.
- **Services** -- SYSTEM hive `...\Services`; correlate installs with 7045.
- **Scheduled tasks** -- `C:\Windows\System32\Tasks\` XML (parse the Actions
  and Triggers); correlate 4698 / TaskScheduler 106.
- **WMI event subscriptions** -- `__EventFilter`, `__EventConsumer`,
  `__FilterToConsumerBinding` in the OBJECTS.DATA repository;
  `Get-WMIObject -Namespace root\subscription -Class __EventConsumer`.
- **Startup folders** -- `...\Start Menu\Programs\Startup\` (per-user and
  All Users).
- **Winlogon** -- `Shell`, `Userinit`, `Notify` under
  `...\Winlogon`; anything appended after `explorer.exe` / `userinit.exe`.
- **IFEO** -- `Image File Execution Options\<exe>\Debugger` (and
  `GlobalFlag` + Silent Process Exit) hijacking a legit binary.
- **COM hijacks** -- user-hive `Software\Classes\CLSID\...\InprocServer32`
  shadowing a HKLM CLSID.
- **LSA / SSP** -- `...\Lsa\Security Packages` and `Notification Packages`;
  `...\Lsa\OSConfig`.
- **BITS jobs** -- `bitsadmin /list /allusers /verbose` or parse
  `...\Microsoft\Network\Downloader\qmgr*.dat` for download-and-execute jobs.

```cmd
:: Autoruns from Sysinternals, offline against a mounted image, VirusTotal + verify
autorunsc.exe -accepteula -a * -h -s -c -o autoruns.csv "\\?\E:\mount"
:: RECmd has batch files that dump every autostart location from the hives
RECmd.exe -d E:\out\host01 --bn BatchExamples\RegistryASEPs.reb --csv E:\out\parsed
```

## Lateral-Movement Traces

Movement leaves paired artifacts on source and destination. Correlate by time,
account, and source IP.

- **Network logons** -- destination Security **4624 Type 3** (SMB/admin
  shares, PtH) and **Type 10** (RDP); **4648** on the source. A Type 3 with
  **NTLM** to a domain-joined host where Kerberos was expected is a
  pass-the-hash signature. A Type 9 (NewCredentials) points to
  Overpass-the-Hash / `runas /netonly`.
- **PsExec / service-based exec** -- **7045** service install (random or
  `PSEXESVC`-style name) plus **7036** start on the destination; **5145** if
  detailed file-share auditing logged the `\ADMIN$\<svc>.exe` write. RemCom and
  similar clones follow the same 7045+7036 pattern.
- **WMI / WinRM exec** -- WMI-Activity **5857-5861**, `wmiprvse.exe` spawning a
  child in Sysmon 1; WinRM over **5985/5986** (HTTP/HTTPS), with
  `Microsoft-Windows-WinRM/Operational` and 4624 Type 3.
- **Admin-share access** -- `C$`, `ADMIN$`, `IPC$` in **5140/5145**;
  correlate with the tool written to `ADMIN$`.
- **SMB / file staging** -- 5140/5145 and `$MFT` entries for tools dropped to
  the destination.

## Filesystem Forensics

The NTFS metadata files are the ground truth the attacker is least likely to
scrub, and the timestomp check that no cleared log defeats.

```cmd
:: $MFT -- every file's four SI + four FN timestamps, parent, size, resident data
MFTECmd.exe -f "E:\out\host01\$MFT" --csv E:\out\parsed
:: USN change journal -- creates/deletes/renames even after the file is gone
MFTECmd.exe -f "E:\out\host01\$Extend\$J" --csv E:\out\parsed
:: $LogFile -- transactional, can recover changes the USN rolled past
```

- **Timestomp detection.** `$STANDARD_INFORMATION` times are settable from
  user land (SetFileTime, `timestomp`); `$FILE_NAME` times are set only by the
  kernel on rename/move. SI **earlier than** FN, sub-second zeros on SI, or SI
  disagreeing with the USN entry all flag forgery. Parse both from MFTECmd and
  diff them.
- **USN Journal** (`$Extend\$UsnJrnl:$J`) records the filename, reason
  (FileCreate, RenameNew, FileDelete), and USN for changes -- reconstructs
  drop, rename, and cleanup of tooling even after deletion.
- **Recycle Bin** -- `$I` files in `C:\$Recycle.Bin\<SID>\` hold the original
  path, size, and deletion time of each `$R` file (`RBCmd.exe`).
- **Shellbags** (UsrClass.dat / NTUSER.DAT) prove a user browsed a specific
  folder, including deleted, external, and network paths -- `SBECmd.exe -d
  E:\out\host01 --csv E:\out\parsed`.
- **Alternate Data Streams** -- `dir /r`, `Get-Item -Stream *`;
  `Zone.Identifier` marks downloaded files (mark-of-the-web) and named streams
  hide payloads.

## Browser and Account Artifacts

- **Browser history / downloads** -- Chrome/Edge `History` (SQLite,
  `...\User Data\Default\History`), Firefox `places.sqlite`; the `downloads`
  table plus `Zone.Identifier` ADS establish what was pulled onto the host.
- **Local accounts** -- SAM hive for created/enabled accounts, RID, last
  logon; correlate with Security 4720/4722/4732.
- **RDP cache / bitmaps** (`...\Terminal Server Client\Cache\*.bmc`) can
  reconstruct what an interactive intruder saw.

## Anti-Forensics Detection

Cleanup is signal, not silence. Hunt the traces of it:

- **Log clears** -- Security **1102** (Security log cleared) and System **104**
  (any log cleared) name the account and time. An event-log **gap** with no
  corresponding shutdown is itself a finding.
- **Timestomping** -- SI vs. FN disagreement (above).
- **Prefetch disabled** -- `...\Memory Management\PrefetchParameters\EnablePrefetcher = 0`.
- **USN journal deleted** -- `fsutil usn deletejournal` leaves the journal
  truncated; note the missing history as a gap.
- **Sysmon / EDR tampering** -- service stop (7036/7045 for the driver),
  config change, or a v2 PowerShell downgrade to dodge script-block logging.

State every such gap explicitly in the timeline as a limitation -- never let a
cleared log become an implicit "nothing happened."

## Building the Super-Timeline

Fast triage first, then the full timeline. Normalize everything to **UTC**,
cite the source artifact on every row, and separate observed from inferred.

```cmd
:: Chainsaw -- fast EVTX triage with built-in + Sigma rules, minutes not hours
chainsaw hunt E:\out\host01\...\winevt\Logs -s sigma\ ^
  --mapping mappings\sigma-event-logs-all.yml -r rules\ --csv -o chainsaw_out

:: Hayabusa -- EVTX -> single timeline scored by severity, Sigma-backed
hayabusa.exe csv-timeline -d E:\out\host01\...\winevt\Logs -o hayabusa.csv -p verbose
```

```bash
# Plaso -- ingest the whole triage set (or image) into one storage file...
log2timeline.py --storage-file plaso.db E:\out\host01
# ...then filter and export the super-timeline
psort.py -o l2tcsv -w super.csv plaso.db "date > '2026-07-01 00:00:00'"
```

Load the parsed CSVs (EZ Tools output, Chainsaw, psort) into **Timeline
Explorer** to pivot, tag, and color across artifacts in one grid. The Eric
Zimmerman suite -- **PECmd, AmcacheParser, AppCompatCacheParser, SrumECmd,
MFTECmd, RECmd, SBECmd, JLECmd, LECmd, RBCmd** -- plus **Chainsaw / Hayabusa**
for EVTX and **Plaso** for the union timeline is the core toolchain. Write
detections for what you find with `writing-sigma-rules`; hand the narrative to
`reporting-security-findings`.

## Rationalizations to Reject

- *"The Security log was cleared, so we're blind."* Sysmon, Prefetch, Amcache,
  SRUM, and the USN journal each independently record execution. A 1102 is
  itself an indicator, and it names the account that cleared it.
- *"No Prefetch entry, so it never ran."* Prefetch is off on most Servers and
  disabled on some SSD systems. Amcache, Shimcache, SRUM, 4688, and Sysmon 1
  all corroborate execution independently.
- *"Shimcache shows it, so it executed."* Shimcache/AppCompatCache records that
  a file was *seen* by the shim engine, not that it ran. Confirm with Prefetch,
  Amcache, or a process-creation event.
- *"The file timestamps look old, so it's original."* `$STANDARD_INFORMATION`
  is trivially forged. Check `$FILE_NAME` and the USN journal; disagreement is
  the finding.
- *"There's no EDR, so there's nothing to analyze."* The registry, event logs,
  prefetch, amcache, SRUM, and $MFT exist on every Windows host regardless of
  EDR. Most of this investigation predates EDR entirely.
- *"One host alerted, so the intrusion is one host."* Correlate 4624 Type
  3/10, 4648, and 7045 outward -- lateral movement is the default assumption
  until auth logs rule it out.
- *"PowerShell was obfuscated, so we can't read it."* Script-block logging
  (4104) records the *deobfuscated* content Windows actually executed. If 4104
  is missing, that gap points to a v2 downgrade -- itself a finding.

## References

- `analyzing-linux-persistence` -- the same host-forensic sweep for Linux
- `responding-to-incidents` -- the IR process and multi-host coordination this
  feeds
- `analyzing-memory-images` -- RAM analysis for the volatile half of the host
- `investigating-m365-entra` -- when the compromise is in cloud identity
- `hunting-threats` -- proactive fleet-wide hunting with no specific host
- `establishing-persistence` -- offensive view of the autostarts hunted here
- `writing-sigma-rules` -- detections for the event-log patterns found
- `reporting-security-findings` -- turning the timeline into the deliverable
- Eric Zimmerman tools (https://ericzimmerman.github.io) -- PECmd,
  AmcacheParser, MFTECmd, RECmd, SBECmd, Timeline Explorer
- KAPE (Kroll Artifact Parser and Extractor) -- triage collection and parsing
- Chainsaw and Hayabusa -- fast Sigma-backed EVTX triage
- Plaso / log2timeline -- super-timeline generation
- Autoruns (Sysinternals) -- autostart enumeration
- Velociraptor -- endpoint triage collection at scale
