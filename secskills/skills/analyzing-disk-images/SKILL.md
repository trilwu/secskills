---
name: analyzing-disk-images
description: Perform dead-disk forensics on an acquired disk image using The Sleuth Kit, Plaso, and bulk_extractor — verify integrity and mount read-only, map partitions, recover deleted files, build a file-system and super-timeline, carve unallocated space, mine registry hives and OS artifacts, and detect anti-forensics. Use when handed a .E01/.dd/.raw/.vmdk/.vhdx disk image or forensic acquisition to examine, recovering deleted files, building a file-system timeline, or carving artifacts from unallocated space.
---

# Analyzing Disk Images

A disk image is a frozen crime scene, and the whole discipline is preserving
that. Work only from a verified, read-only copy, prove nothing changed with
hashes at every step, and remember that the deleted and the unallocated often
say more than the live file system — because that is exactly what someone tried
to remove.

## When to Use

- You have an acquired disk image (`.E01`, `.dd`/`.raw`, `.aff4`, `.vmdk`, `.vhdx`) to examine
- Recovering deleted files, or reconstructing what was on a wiped or reformatted volume
- Building a file-system timeline or a full super-timeline across the whole image
- Carving files and artifacts out of unallocated space, slack, and free clusters
- Mining registry hives, browser data, logs, or other artifacts offline from a mounted image
- Confirming or refuting anti-forensics — timestomping, wiping, hidden or encrypted containers

## When NOT to Use

- **You have a RAM capture, not a disk image** — use `analyzing-memory-images`
- **You have a live or triage Windows host and want the artifact-by-artifact
  investigation, not raw image handling** — use `investigating-windows-endpoints`
- **You are sweeping a live Linux host for persistence** — use `analyzing-linux-persistence`
- **You need the wider incident-response process — scoping, containment,
  eradication** — use `responding-to-incidents`
- **You recovered a specific sample and want to detonate it** — use `analyzing-malware`

## Acquisition and Integrity

Everything downstream is worthless if the image is not provably the disk. Never
touch the original media without a write blocker, and never analyze the original
image — work on a copy.

```bash
# Acquire to E01 (EWF) with built-in compression and hashing — preferred format
sudo ewfacquire -t /evidence/host01 -f encase6 -c deflate:fast \
     -C "IR-2026-014" -E "1" -D "Dell OptiPlex sda" /dev/sda

# Raw acquisition alternative — dd with error handling, hash inline
sudo dd if=/dev/sda bs=4M conv=noerror,sync status=progress \
     | tee /evidence/host01.dd | sha256sum

# Verify an existing E01 against its stored hashes
ewfverify /evidence/host01.E01

# Hash the working copy and record it — MD5 and SHA-256 both, for legacy tooling
md5sum   /evidence/host01.dd
sha256sum /evidence/host01.dd
```

**Record at acquisition time, not later:**

```
Evidence ID | Source host/serial | Collected by | UTC timestamp | Tool + version
Write blocker used (Y/N + model) | MD5 + SHA-256 at acquisition
SHA-256 verified after each copy | Custodian at each handoff | Storage location
```

Verify the hash after every copy or transfer. A mismatch means stop — you no
longer have the evidence you think you have. If the case may reach litigation or
a regulator, involve legal before acquisition.

**Expose the image as a raw device without altering it.** E01 and AFF4 are
containers; most TSK and mount operations want a raw block device or file.

```bash
# Mount an E01 as a raw device (read-only, FUSE) — exposes ./ewf1
ewfmount /evidence/host01.E01 /mnt/ewf
# /mnt/ewf/ewf1 is now a raw image you can feed to mmls, fls, mount -o loop, etc.

# xmount can also convert on the fly (E01 -> raw or VDI) without a second copy
xmount --in ewf /evidence/host01.E01 --out raw /mnt/xmount
```

## Mounting and Partition Layout

Understand the geometry before you mount anything. The offsets matter — mount at
the wrong one and you see nothing or you see garbage.

```bash
# Sleuth Kit partition table — gives you the starting SECTOR of each volume
mmls /mnt/ewf/ewf1
#   Slot   Start        End          Length       Description
#   002    0000002048   0000206847   0000204800   NTFS / exFAT (0x07)
#   003    0000206848   0976771071   0976564224   NTFS / exFAT (0x07)

# Cross-check with fdisk
fdisk -l /mnt/ewf/ewf1

# Loopback-mount a partition read-only. Offset = start_sector * 512.
# 206848 * 512 = 105906176
sudo mount -o ro,noexec,noload,loop,offset=105906176 \
     /mnt/ewf/ewf1 /mnt/evidence
```

`ro,noexec` prevents writes and accidental execution; `noload` stops the kernel
replaying the NTFS journal (a write) on mount. For ext4 use `ro,noload`; the
journal replay is the classic way an examiner silently modifies evidence.

**Layered and encrypted volumes:**

```bash
# LVM — scan and activate, then mount the logical volume read-only
sudo losetup -r -f -P /mnt/ewf/ewf1
sudo pvscan && sudo vgchange -ay
sudo mount -o ro /dev/mapper/vg0-root /mnt/evidence

# LUKS — needs the passphrase or a recovered key file
sudo cryptsetup --readonly luksOpen /dev/loop0p2 evd_crypt
sudo mount -o ro /dev/mapper/evd_crypt /mnt/evidence

# BitLocker — dislocker with a recovery key, clear key, or FVEK
sudo dislocker -r -V /dev/loop0p2 -p<48-digit-recovery-key> -- /mnt/bde
sudo mount -o ro,loop /mnt/bde/dislocker-file /mnt/evidence

# macOS APFS / HFS+ — apfs-fuse for APFS containers, read-only
apfs-fuse -o ro /dev/loop0p2 /mnt/evidence      # APFS
sudo mount -t hfsplus -o ro,loop /dev/loop0p2 /mnt/evidence   # HFS+
```

Without the BitLocker recovery key or LUKS passphrase you have an encrypted
brick — pursue the key (escrow, AD, MDM, a memory image, a sticky note) rather
than attacking the crypto.

## The Sleuth Kit Workflow

TSK reads the file system directly from the image — no mount, no OS
interpretation, and it sees deleted entries the live view hides. Give every TSK
command the offset (`-o` in sectors) so it targets the right partition.

```bash
# List files including deleted (*) ones, recursively, from the NTFS at sector 206848
fls -r -o 206848 /mnt/ewf/ewf1
#   r/r * 5613-128-1:  Users/jdoe/AppData/.../invoice.xlsx   <- deleted

# Detail a specific inode/MFT entry: timestamps, allocation, data runs
istat -o 206848 /mnt/ewf/ewf1 5613

# Extract a file BY INODE, even when deleted, straight out of the image
icat -o 206848 /mnt/ewf/ewf1 5613-128-1 > /evidence/recovered/invoice.xlsx

# Dump all unallocated blocks for carving
blkls -o 206848 /mnt/ewf/ewf1 > /evidence/unalloc.dd

# Bulk-recover every allocated and deleted file TSK can reconstruct
tsk_recover -e -o 206848 /mnt/ewf/ewf1 /evidence/recovered/
```

`icat` on an inode is the cleanest recovery path — if the `$MFT` record and data
runs survive, you get the exact file back, no carving guesswork. **Autopsy** is
the GUI over TSK; it wraps all of the above (fls/istat/icat, keyword indexing,
timelines, carving) in a case-managed interface and is the right tool when you
want to browse rather than script.

## File-System Timelines and the Super-Timeline

The timeline is the deliverable everything else supports. Build two: the fast
file-system timeline first, then the full super-timeline when you need
application-level events.

```bash
# 1. File-system timeline (MAC times) from the whole image via TSK
fls -r -m "/" -o 206848 /mnt/ewf/ewf1 > /evidence/body.txt
mactime -b /evidence/body.txt -d -z UTC > /evidence/fs_timeline.csv
# Filter to a window:
mactime -b /evidence/body.txt -d -z UTC 2026-07-10..2026-07-13 > /evidence/window.csv

# 2. Super-timeline with Plaso across the ENTIRE image (all partitions, all parsers)
log2timeline.py --storage-file /evidence/host01.plaso /mnt/ewf/ewf1

# Render, filtered to the incident window, sorted, UTC
psort.py -o l2tcsv -z UTC \
     -w /evidence/super_timeline.csv /evidence/host01.plaso \
     "date > '2026-07-10 00:00:00' AND date < '2026-07-13 23:59:59'"
```

Plaso parses registry, event logs, prefetch, browser history, LNK files, `$MFT`,
`$UsnJrnl`, and dozens more into one normalized timeline — far richer than MAC
times alone. Load the CSV into **Timeline Explorer** (Eric Zimmerman) to filter,
color, and pivot interactively; a million-row super-timeline is unusable in a
text editor. Everything in UTC, and cite the source artifact per row.

## Deleted-File Recovery and Carving

Two distinct techniques. Recovery uses file-system metadata that still points at
the data; carving ignores metadata entirely and finds files by their content
signatures. Run both.

```bash
# Metadata-based recovery (already shown) — precise, keeps filenames
tsk_recover -e -o 206848 /mnt/ewf/ewf1 /evidence/recovered/

# Signature carving over unallocated space — recovers files whose MFT record is gone
photorec /evidence/unalloc.dd            # interactive; broadest format support
foremost -o /evidence/foremost -c /etc/foremost.conf /evidence/unalloc.dd
scalpel -o /evidence/scalpel /evidence/unalloc.dd    # foremost successor, configurable

# bulk_extractor — structured artifacts across the RAW image, no file system needed
bulk_extractor -o /evidence/be_out /mnt/ewf/ewf1
#   emails, URLs, credit-card numbers (with Luhn validation), search terms,
#   PII, EXIF, PGP keys, and *_histogram.txt files. Read the histograms first —
#   frequency-stacked domains and emails surface C2 and exfil targets fast.
```

Carve from `blkls` output when you specifically want deleted content; carve from
the full raw image when you want everything including file slack. Carved files
have no timestamps and no names — correlate them back to the timeline by content
and location.

## The Artifact Goldmine by OS

Deleted files are half the story. The high-value forensic artifacts are the
system's own records of what ran, what connected, and what was opened.

**Windows** — mount read-only, then pull the hives and journals:

```bash
# Registry hives (system-wide + per-user)
#   SOFTWARE, SYSTEM, SAM   -> C:\Windows\System32\config\
#   NTUSER.DAT              -> C:\Users\<user>\
RECmd.exe --f "/mnt/evidence/Windows/System32/config/SYSTEM" --bn Services.reb
rip.pl -r /mnt/evidence/Windows/System32/config/SOFTWARE -f software  # RegRipper

# NTFS journals — extract by inode with icat, then parse
#   $MFT (0), $LogFile (2), $UsnJrnl:$J
icat -o 206848 /mnt/ewf/ewf1 0-128-1 > /evidence/\$MFT
MFTECmd.exe -f "/evidence/\$MFT" --csv /evidence/ --csvf mft.csv
```

Windows artifact analysis runs deep — prefetch, amcache, shimcache, shellbags,
jumplists, event logs, SRUM. For that artifact-by-artifact investigation hand off
to `investigating-windows-endpoints`; here, extract the raw hives and journals
from the image and pass them on intact.

**Linux** — the evidence is text and it is where you expect it:

```bash
#   /var/log/{auth.log,syslog,secure,journal}   authentication + system events
#   /home/*/.bash_history, /root/.bash_history  command history
#   /etc/{crontab,cron.d,rc.local}, /etc/systemd, ~/.ssh/authorized_keys
#   /etc/passwd, /etc/shadow, /etc/ld.so.preload  accounts + preload persistence
grep -aiE "sudo|ssh|useradd|wget|curl" /mnt/evidence/var/log/auth.log
```

For a systematic init-path persistence sweep, follow `analyzing-linux-persistence`.

**macOS** — unified logs and property lists:

```bash
#   /var/db/diagnostics/*.tracev3          unified log (parse with `log show`)
#   /Library/LaunchDaemons, ~/Library/LaunchAgents   persistence plists
#   ~/Library/Preferences/*.plist          app state, recent items
plutil -p /mnt/evidence/Library/LaunchDaemons/com.suspect.plist
```

## Registry and Hive Mining

Offline hive parsing is one of the richest sources on a Windows image — it
records execution, device history, and user activity that no log retains.

```bash
# Autoruns / persistence from the hives
rip.pl -r /mnt/evidence/Windows/System32/config/SOFTWARE -p soft_run
RECmd.exe --f "/mnt/evidence/.../NTUSER.DAT" --bn RunMRU.reb --csv /evidence/

# LastWrite times on keys are effectively per-key timestamps — treat them as evidence
# Shellbags — folders a user browsed, including now-deleted/removable paths
SBECmd.exe -d /mnt/evidence/Users/jdoe -o /evidence/shellbags/
# USB device history — SYSTEM\MountedDevices, USBSTOR; SOFTWARE\...\Windows Portable Devices
rip.pl -r /mnt/evidence/Windows/System32/config/SYSTEM -p usbstor
```

Key LastWrite times let you place configuration and persistence changes on the
timeline. Shellbags and USBSTOR routinely prove access to data and use of
removable media that the live file system no longer shows.

## Anti-Forensics and Hidden Data

Assume the subject tried to hide something. The traces of hiding are themselves
findings.

- **Timestomping** — `$STANDARD_INFORMATION` times are trivially forged; the
  `$FILE_NAME` attribute in the `$MFT` is not. When they disagree, or when
  sub-second precision is suspiciously zeroed, that is evidence of tampering.
  `MFTECmd` surfaces both; compare them.
- **Wiping traces** — a file whose `$MFT` record survives but whose data runs
  point at overwritten clusters, gaps in inode numbering, or wiper artifacts
  (`sdelete`, `BleachBit`) in prefetch/amcache.
- **Slack space** — file slack and volume slack hold fragments of previously
  resident data; `blkls -s` extracts slack specifically.
- **Alternate Data Streams** — NTFS ADS hide data off the primary stream:
  `fls -r` shows them as extra `:stream` entries; `istat` lists every `$DATA`
  attribute.
- **Steganography hints** — images far larger than their visible content,
  known stego-tool artifacts, appended data after a file's logical EOF.
- **Encrypted containers** — VeraCrypt/TrueCrypt volumes look like
  high-entropy files with no header and a size that is a round multiple;
  a hidden volume lives in the free space of an outer volume. `bulk_extractor`'s
  entropy view and file-size outliers flag candidates.

```bash
# Enumerate ADS across a mounted NTFS image
fls -r -o 206848 /mnt/ewf/ewf1 | grep ':'
# Extract slack for carving
blkls -s -o 206848 /mnt/ewf/ewf1 > /evidence/slack.dd
```

## String and Keyword Search at Scale

When you do not know where the answer is, or need to validate a hypothesis
across the whole disk.

```bash
# bulk_extractor is the scalable default — indexed, structured, histogrammed
bulk_extractor -o /evidence/be_out /mnt/ewf/ewf1
grep -f keywords.txt /evidence/be_out/*_histogram.txt

# Raw strings + grep on the image (ASCII and UTF-16LE), when you need a specific token
strings -a -t d      /mnt/ewf/ewf1 | grep -aiF -f keywords.txt
strings -a -t d -e l /mnt/ewf/ewf1 | grep -aiF -f keywords.txt

# YARA across the entire raw image — malware and IOC hunting on disk
yara -s -r /evidence/rules/incident.yar /mnt/ewf/ewf1
```

For writing effective YARA against disk artifacts — unpacked-form strings, config
blocks, tight condition logic — see `writing-yara-rules`. Feed the `-t d` byte
offset from a strings hit back into `mmls`/`ifind` to map a raw offset to a file.

## Reporting the Timeline and Handing Off

The disk analysis is one input to a larger investigation. Package it so the next
stage can use it without re-deriving your work.

- **Deliver the timeline** — UTC, one source artifact cited per row, observed
  vs inferred marked separately. See `reporting-security-findings` for structure.
- **Evidence register** — image IDs, acquisition and verification hashes,
  custody, every recovered file with its source inode/offset.
- **Route the volatile evidence** — a memory image or hibernation/page file you
  recovered goes to `analyzing-memory-images`; a recovered executable or
  document to detonate goes to `analyzing-malware`.
- **State the gaps** — wiped regions, missing partitions, encryption you could
  not open, and log retention limits, explicitly, so they are not read as
  "nothing was there."

## Rationalizations to Reject

- *"The file was deleted, so it's gone."* Until the clusters are reused it is
  recoverable from unallocated space, and the `$MFT` record with its data runs
  often survives — `icat` or `tsk_recover` reconstructs it exactly.
- *"I'll just mount it and browse."* Mount read-only and hash first, or you have
  altered the evidence. A default mount replays the journal — that is a write to
  the thing you are trying to preserve.
- *"The hash can wait until I'm done."* Hash at acquisition or you can never
  prove the image matches the disk, and a defense expert will say so. Integrity
  is established at collection or not at all.
- *"The live file system shows everything relevant."* It hides deleted entries,
  ADS, slack, and unallocated data — precisely where someone puts what they want
  gone. The live view is the smallest part of the disk.
- *"The timestamps tell me when it happened."* `$STANDARD_INFORMATION` is
  forgeable in seconds; trust `$FILE_NAME`, `$UsnJrnl`, and LastWrite times, and
  treat disagreement between them as a finding, not noise.
- *"It's encrypted, so there's nothing I can do."* Pursue the key — escrow, AD,
  MDM, a recovered memory image, unallocated space where a passphrase or FVEK may
  linger — before concluding the volume is unreadable.
- *"Carving gave me the files, that's enough."* Carved files have no metadata,
  no names, no timestamps. Correlate them to the file-system timeline and inode
  source, or you cannot say where they came from or when.

## References

- `analyzing-memory-images` — a recovered RAM capture, hiberfil, or pagefile
- `investigating-windows-endpoints` — artifact-by-artifact Windows investigation
- `analyzing-linux-persistence` — systematic init-path persistence sweep
- `responding-to-incidents` — the wider IR process this feeds
- `analyzing-malware` — detonating a recovered sample
- `writing-yara-rules` — YARA for scanning the image and carved output
- `reporting-security-findings` — structuring the timeline and evidence register
- The Sleuth Kit / Autopsy (sleuthkit.org), Plaso / log2timeline (plaso.readthedocs.io)
- bulk_extractor (github.com/simsong/bulk_extractor), PhotoRec / foremost / scalpel
- libewf / ewf-tools (ewfacquire, ewfverify, ewfmount), RegRipper, Eric Zimmerman tools
  (MFTECmd, RECmd, SBECmd, Timeline Explorer)
