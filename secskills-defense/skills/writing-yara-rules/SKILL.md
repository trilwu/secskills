---
name: writing-yara-rules
description: Author durable YARA detection rules — meta/strings/condition anatomy, string types and modifiers, structural conditions with file magic and offsets, the PE/ELF/math/hash modules, specificity-vs-durability tuning, atom-aware performance, memory and process scanning, and YARA-X. Use when writing a YARA rule, creating a signature for a malware family or a file/memory artifact, turning IOCs or a captured sample into a detection, or hunting for a family across a corpus with Retrohunt or an on-host scanner.
verified: 2026-07-26
---

# Writing YARA Rules

A good YARA rule matches the malware's *nature* — its code, its structure, its
unavoidable constants — not its *costume*, which is a filename or a mutable
string that changes on the next build. Match the nature and the rule survives
recompilation and catches the whole family; match the costume and you catch one
sample once. The entire craft is choosing strings and a condition that are both
specific enough to avoid false positives and durable enough to generalize.

## When to Use

- Writing a YARA rule to detect a malware family, tool, or capability
- Creating a signature for a file or in-memory artifact from a known sample
- Turning IOCs or a captured specimen into a portable, testable detection
- Hunting for a family across a corpus (VirusTotal Retrohunt, LOKI/THOR, on-host scan)
- Clustering related samples by shared code, constants, or structure
- Reviewing or tuning an existing rule for false positives and scan performance

## When NOT to Use

- **The detection belongs in log or SIEM telemetry, not on files or memory** —
  use `writing-sigma-rules`
- **Choosing what to detect and where it should live, the strategy above rule
  syntax** — use `engineering-detections`
- **You do not yet understand the sample well enough to pick durable anchors** —
  use `analyzing-malware` first
- **Running the hunt rather than authoring the signature** — use `hunting-threats`
- **Packaging IOCs, attribution, and a finished report** — use
  `producing-threat-intelligence`

## Rule Anatomy

Three sections: `meta` (documentation, never matched on), `strings` (the
patterns), `condition` (the boolean that decides a hit).

```yara
import "pe"

rule Family_Loader_v1
{
    meta:
        author      = "analyst"
        date        = "2026-07-26"
        description = "ExampleLoader stage-1, config-decode stub + family constants"
        hash        = "a1b2c3...<sha256 of the analyzed sample>"
        reference   = "https://internal/case/1234"
        version     = "1"
        tlp         = "amber"
    strings:
        $decode = { 8A 04 0? 32 0? 88 0? 4? 3B ?? 72 }
        $marker = "cfg::begin" ascii
        $mutex  = "Global\\ExL-%08x" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and 2 of them
}
```

**Meta fields that matter.** `author` and `date` for provenance; `hash` records
the exact sample the rule was derived from so a future analyst can re-verify;
`reference` links the case or report that justifies it; `description` states
what and why. Meta is free-form text — YARA never evaluates it — so treat it as
the rule's changelog. Add `version`/`tlp`/`score` fields your tooling consumes.

## Strings and Modifiers

**Text strings** are the default. **Hex strings** match raw bytes and support
wildcards and jumps. **Regex** is written between slashes.

```yara
strings:
    $text  = "Mozilla/5.0 (Custom-UA)" ascii wide
    // Hex: ?? = any byte, 0? = any low nibble, [4-6] = 4 to 6 arbitrary bytes
    $hex   = { 55 8B EC 83 EC ?? 53 56 57 [4-6] E8 ?? ?? ?? ?? }
    $re    = /\/gate\/[a-f0-9]{16}\.php/ nocase
```

Modifiers change how a string matches. Chain those that combine.

| Modifier | Effect |
| --- | --- |
| `nocase` | Case-insensitive text/regex match |
| `wide` | Match UTF-16LE (two bytes per char) — most Windows strings |
| `ascii` | Match single-byte form; pair with `wide` to match both |
| `fullword` | Match only when bounded by non-alphanumeric bytes |
| `xor` | Match all 256 single-byte XOR-encoded variants (keys 0x00-0xFF) |
| `xor(0x01-0xff)` | XOR over a bounded key range |
| `base64` / `base64wide` | Match the three base64-encoded alignments |
| `private` | Match is never shown in output (`-s`/callback); still counts in `of them` |

`xor` finds strings hidden behind a one-byte key without knowing the key;
`base64` catches config values embedded in encoded blobs. Both cost scan time —
use them when you have evidence the encoding is present, not by default.

## Building Durable Conditions

The condition is where specificity lives. Beyond `all of them` / `N of them`:

```yara
condition:
    // Anchor on file type before touching strings — cheap and decisive
    uint16(0) == 0x5A4D and              // MZ (PE)
    uint32(0) == 0x464C457F and          // 0x7F 'E' 'L' 'F' (ELF)

    // Offset constraints
    $magic at 0 and                      // string must sit at offset 0
    $tag in (0..1024) and                // within the first 1 KB
    #beacon >= 3 and                     // the $beacon string appears 3+ times

    // Bound the search — a 40-byte dropper is not a 50 MB installer
    filesize < 500KB and

    // Quorum across a candidate set, resilient to any one string changing
    3 of ($cfg*) and

    // for..of: k of a set, with a per-match predicate
    for any i in (1..#url) : ( @url[i] < 0x2000 )
```

`#string` is the match count, `@string[i]` the offset of the i-th match,
`!string[i]` its length. `for..of` expresses "any/all/N of these strings, each
satisfying a condition" — the tool for rules like "an RWX marker within 100
bytes of a known stub." Anchoring on `uint*` magic first lets the engine skip
non-matching files before scanning strings, which is both correctness and speed.

## Specificity vs. Durability

Every rule sits on a line between too-broad (false positives) and too-narrow
(catches one build). Aim for a **cluster of family-specific constants plus one
structural anchor.**

Bad — a single common string, matches half of goodware:

```yara
rule Bad_TooBroad {
    strings:
        $ = "GetProcAddress"
    condition:
        $
}
```

Bad — a filename, the definition of a costume; the family renames it per campaign:

```yara
rule Bad_Filename {
    strings:
        $ = "svch0st_updater.exe" nocase
    condition:
        $
}
```

Good — several constants the author cannot casually change, gated by file type
and size, requiring a quorum so one mutated string does not break the rule:

```yara
rule Good_FamilyCluster {
    meta:
        description = "ExampleRAT: config key schedule + mutex fmt + UA"
    strings:
        $keysched = { 66 0F 6F 05 ?? ?? ?? ?? 66 0F EF C8 66 0F 7F 4? }
        $mutexfmt = "ExR-{%04x-%04x}" ascii
        $ua       = "X-ExR-Build:" ascii wide
        $err      = "cfg decrypt failed @stage%d" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3MB and 3 of them
}
```

The good rule generalizes because its anchors are things the malware *needs* —
its own key schedule, its own mutex format, its own diagnostic strings — not
things an operator flips between deployments.

## Using the Modules

Modules expose parsed structure. `import` at the top of the file.

**PE** — the highest-value module for Windows samples:

```yara
import "pe"
rule PE_Structural {
    condition:
        pe.is_pe and
        pe.imphash() == "d2a6...<import hash>" and       // API import fingerprint
        pe.number_of_sections == 5 and
        pe.imports("wininet.dll", "InternetOpenA") and
        pe.exports("PluginInit") and
        for any s in pe.sections : ( s.name == ".xdata" and s.raw_data_size == 0 ) and
        pe.rich_signature.length > 0 and                 // Rich header (compiler fingerprint)
        pe.timestamp > 1577836800
}
```

`imphash` clusters samples built from the same import table; the Rich header
fingerprints the build toolchain and is hard to forge; `pe.imports`/`pe.exports`
anchor on capability rather than incidental bytes.

**ELF** mirrors PE for Linux (`elf.number_of_sections`, `elf.type`,
`elf.symtab`). **math** scores regions — flag packed or encrypted blobs:

```yara
import "math"
rule Packed_HighEntropy {
    condition:
        uint16(0) == 0x5A4D and
        math.entropy(0x1000, filesize - 0x1000) >= 7.2 and   // near-random tail
        math.mean(0, filesize) > 100
}
```

**hash** computes digests inside the condition — useful to pin a specific
embedded resource, not the whole file (a whole-file hash needs no YARA):

```yara
import "hash"
rule EmbeddedResource {
    condition:
        hash.sha256(0x400, 0x200) == "e3b0c4...<digest of the fixed config blob>"
}
```

## Targeting Position-Independent Things

Anchor on what moves with the code, not with the campaign. In rough order of
durability: crypto constants (S-boxes, MD5/SHA init values, custom key
schedules) → the family's own mutex/pipe/registry name templates → config
markers and delimiters → C2 URI templates (`/gate/`, `/panel/upload.php`) →
unique error and debug strings the developer left in → stack strings once you
have deobfuscated them with `floss`. A filename, a compile timestamp, a
campaign C2 IP, and a single common Win32 API name are *not* durable — they are
the costume.

## Killing False Positives

A rule is not done when it hits the sample; it is done when it does not hit
goodware. Three levers, applied together:

- **Quorum** — require `N of M` strings, never a lone common one. Any single
  string can appear in benign software; three family constants together will not.
- **File-type anchor** — lead the condition with `uint16(0) == 0x5A4D` or the
  ELF magic so the rule never even scans an unrelated file type.
- **Size bound** — `filesize < N`. A 20 KB loader is not a 200 MB game client;
  the bound removes whole categories of coincidental matches for free.

## Testing and Validation

Validation is not optional. An untested rule is a future false-positive storm.

```bash
yara -w rule.yar sample                 # -w suppresses warnings; does it fire?
yara -s -w rule.yar sample              # -s prints which strings matched, and where
yara -w -r rule.yar ./samples/family/   # -r recurse: must hit every known-true sample
yara -w -r rule.yar ./corpus/goodware/  # must produce ZERO hits — the load-bearing step
yara -C rules.yarc ...                  # compile once, scan many with the compiled form
```

**Atoms and why 4+ byte anchors matter.** YARA scans by extracting short
fixed-byte substrings — *atoms* — from each string and searching for those
first; a match on an atom triggers full verification of the string. A string
whose only fixed run is 1-2 bytes (an over-wildcarded hex pattern, a two-letter
text string) yields a weak atom that matches constantly, forcing verification on
nearly every file and collapsing performance. Give every string at least one run
of 4+ contiguous non-wildcard bytes. YARA warns on slow strings and short atoms
at compile time — drop `-w` (which suppresses them) and treat those warnings as
errors. Avoid unbounded and catastrophic regex
(`.*`, nested quantifiers); prefer bounded classes and jumps. Profile with
`yara -S` (`--print-stats`, per-rule statistics) when a ruleset drags.

## Memory and Process Scanning

File rules and memory rules are not interchangeable. A rule anchored on
`uint16(0) == 0x5A4D` and PE sections will not fire on a process where the
payload is unpacked, relocated, and has no on-disk header.

```bash
yara -w rule.yar mem.dmp                # scan a memory dump / minidump
yara -w rule.yar 4242                   # scan a live process — the PID is the final argument
yara -w -s rule.yar 4242                # -s prints which strings matched in the process, and where
```

For memory rules, drop the file-magic anchor and the `filesize` bound (a process
has no meaningful filesize); anchor instead on the *decoded* strings and code
that only exist after unpacking — the plaintext config, the C2 template, the
stack strings assembled at runtime. Keep file-scan and memory-scan rules
separate, or gate the file-only conditions so the same rule can serve both.

## YARA-X: the Modern Engine

YARA-X is the Rust rewrite and the direction of travel: faster, safer, better
diagnostics, and largely source-compatible. Author new rules to run under both
where practical. Differences to know:

- CLI is `yr` (e.g. `yr scan rule.yar sample`, `yr compile`, `yr fmt` to format).
- Stricter parsing rejects some ambiguous legacy rules; the negative-index and a
  few deprecated constructs are gone; `include` and module semantics tightened.
- Improved regex engine and clearer performance warnings; `yr fmt` and a
  language server ship in-box.
- Some third-party modules from classic YARA are not all ported — check before
  relying on an exotic module.

Test the same rule under both engines when your deployment fleet is mixed
(LOKI/THOR and older scanners run classic YARA; newer pipelines run YARA-X).

## Organizing and Sharing Rules

- **Rule sets** — one file per family or campaign, `include "base.yar"` to share
  helpers; compile a directory into a single `.yarc` for distribution.
- **Private rules** — `private rule` never reports on its own; reference it from
  public rules as a reusable predicate (a shared "is a Windows PE" gate, a shared
  packer detector). Keeps conditions DRY and readable.
- **Tags** — `rule Foo : loader family_x { ... }`; filter at scan time with
  `yara --tag loader`. Tag by role and family so hunts can select subsets.
- **External variables** — `yara -d ext=value` (or `-x module=path`); reference
  `ext` in conditions to make one rule behave differently per environment
  (e.g. a filename/filepath passed by the scanning host).
- **Metadata discipline** — consistent `author`/`date`/`reference`/`hash`/score
  fields let downstream tooling (THOR, VT, your CI) sort, score, and attribute.

```yara
private rule is_pe {
    condition: uint16(0) == 0x5A4D and filesize < 10MB
}

rule Family_X_Loader : loader family_x {
    meta:
        author = "analyst"
        score  = 75
    strings:
        $a = "ExL-%08x" ascii
        $b = { 8A 04 0? 32 0? 88 0? 4? 3B ?? 72 }
    condition:
        is_pe and all of them
}
```

## Rationalizations to Reject

- *"I hashed the sample, that's a rule."* A hash matches exactly one file and
  nothing else. The next build has a different hash. That is an IOC, not a
  detection.
- *"It matched the sample, ship it."* A rule untested against a goodware corpus
  is an unexploded false-positive storm. Scanning the sample proves nothing about
  what else it hits.
- *"One good string is enough."* One string is one mutation away from useless,
  and common strings appear everywhere. Require a quorum of family constants.
- *"I'll wildcard the whole function to be safe."* Over-wildcarded hex leaves no
  4-byte atom, so the rule matches on a weak anchor and destroys scan
  performance. Keep real byte runs.
- *"The filename is distinctive, use it."* Filenames are the costume — renamed
  per campaign at zero cost to the operator. Anchor on code and structure.
- *"It works on the file, so it works in memory."* File-magic and section
  anchors do not exist in an unpacked process image. Memory needs its own rule.
- *"Broad now, tune later."* Every noisy hit in production burns analyst trust
  and buries real matches. Tune before you deploy, not after.

## Reading External Sources

Fetch public advisories, specifications, and vendor reports as Markdown:

```bash
curl -sL "https://defuddle.md/<url>"      # scheme in the path is optional
```

This strips page boilerplate — roughly 78% fewer tokens on a prose page — and
returns the full text rather than a summary, so you can grep it and trust a
negative result.

Three things it is not for. Fetch JSON and API responses raw, because
readability extraction mangles structured data. Fetch authenticated or
JavaScript-rendered pages directly, because it retrieves them anonymously. And
never route **adversary infrastructure** (phishing links, C2, malware hosting),
**client-owned hosts**, or **engagement URLs** through it — the request leaves
your machine to a third party, and for live adversary infrastructure it also
tips off the operator.

## References

- `writing-sigma-rules` — the same craft for log and SIEM telemetry
- `engineering-detections` — choosing what to detect and where it belongs
- `analyzing-malware` — understanding the sample that a durable rule is built from
- `hunting-threats` — running the hunt these signatures drive
- `producing-threat-intelligence` — packaging IOCs, attribution, and reporting
- `reporting-security-findings` — writing up what the detection found
- YARA (VirusTotal) and YARA-X — the engines and their documentation
- yarGen — auto-generate candidate rules and strings from samples (a starting
  point, never a finished rule)
- yara-validator / `yr fmt` — lint and normalize rules in CI
- LOKI and THOR (Nextron) — IOC and YARA scanners for on-host hunting
- VirusTotal Retrohunt — run a rule across VT's corpus to find related samples
