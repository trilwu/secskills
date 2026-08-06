---
name: diffing-binary-patches
description: Locate the vulnerability a security patch fixes by diffing the pre- and post-patch binaries — using BinDiff, Diaphora, or ghidriff to find the changed functions, reading the added checks to recover the bug class, and reasoning back to a reachable pre-patch trigger for 1-day analysis. Use when comparing two versions of a DLL/ELF, extracting a Microsoft patch from an MSU/MSP for delta comparison, or turning a vague advisory into the exact code that changed.
verified: 2026-08-07
---

# Diffing Binary Patches

A security patch is a description of a vulnerability written in the vendor's own
code. Diffing the binary before and after the fix turns a one-line advisory into
the exact function, the exact check that was added, and — reasoning backward —
the input that reached the bug before the patch. This is the core of 1-day
analysis: the fix tells you where to look, the diff tells you what, and the
pre-patch reachability tells you how.

## When to Use

- Comparing two versions of the same binary (DLL, ELF, driver) to find what a
  security update changed
- Turning a CVE advisory or Patch-Tuesday bulletin into the specific vulnerable
  code
- Extracting a Microsoft patch (MSU/MSP/cab, delta-compressed) into a full
  binary you can diff
- Assessing whether a "silent" fix in a new release closed a security bug

## When NOT to Use

- **Understanding a single binary** with no patched counterpart — that is
  `analyzing-binaries`.
- **Building the working exploit** once the bug and trigger are understood —
  that is `exploiting-memory-corruption` (native) or the relevant web skill.
- **Source-level diffs** (a GitHub commit, a changelog) — read the source with
  `reviewing-code-changes`; binary diffing is for when you only have compiled
  artifacts.
- **Unpacking a protected binary** before it can be diffed — use
  `unpacking-protected-binaries` first.

## Get Two Comparable Binaries

The diff is only as clean as the inputs. You need the same binary at two
versions, same architecture and ideally the same compiler, so the noise is
small enough that the security change stands out.

For Microsoft patches this is a step in itself. Since Windows 10, updates ship
as **forward/reverse delta patches**, not whole files — the MSU contains
compressed deltas, not the finished DLL. Extract the update (expand the MSU/cab)
and apply the delta to your baseline binary to reconstruct the full patched file
(the `PatchExtract` / `delta_patch.py` approach, driving the `msdelta` API).
Diffing the raw delta or a mismatched baseline produces garbage. For most other
software, two release builds or two package versions are directly comparable.

## Find the Changed Functions

Run a binary differ and read its results by similarity, not top to bottom:

- **BinDiff** (open-source, via BinExport from IDA or Ghidra) matches functions
  across the two binaries and scores similarity; the interesting functions are
  the ones that changed *slightly* — a similarity just below 1.0 — not the ones
  that are entirely new or gone.
- **Diaphora** (IDA) does the same with strong heuristics and a good pseudocode
  diff view, which matters because you will read decompiler output to understand
  the change.
- **ghidriff** gives a scriptable, Ghidra-based diff when you want headless or
  CI-style runs.

Expect noise. A compiler change, function reordering, or an unrelated feature
inflates the diff; ASLR and address shifts are not real changes. Filter to
functions whose *logic* changed and ignore pure address churn.

## Read the Fix, Recover the Bug

The added code is the tell. Most security fixes look like one of a small set of
shapes, and each names the bug class:

- **A new bounds or length check** before a copy or index → the pre-patch code
  had an overflow or OOB access on that path.
- **A signedness or integer change** (`size_t` for `int`, an added overflow
  check) → an integer bug feeding an allocation or copy.
- **A new null / state check** → a use-after-free, a race, or an uninitialized
  use the check now prevents.
- **A validation of a field, type tag, or length from parsed input** → the
  parser trusted attacker-controlled data.
- **A reordered free / set-to-null after free** → a UAF or double-free.

Read the *post*-patch function to see what is now enforced, then the *pre*-patch
function to confirm the enforcement was absent. That pair is the vulnerability.

## Reason Back to a Trigger

A changed function is a lead, not a finding, until you can reach it. Trace how
attacker-controlled input arrives at the pre-patch code: which API, message,
file field, or packet reaches the unguarded path, and under what state. If you
cannot construct a path from an untrusted input to the changed code, the change
may be hardening rather than a reachable bug — say so rather than overclaiming.
When the path is real, that reachable trigger is the handoff to exploit
development.

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

Some sites block the extractor and return an error blob rather than the page —
`{"error":"Failed to fetch: 418 I'm a teapot"}` from freedesktop.org, for
instance. That is the fetch being refused, **not** the source saying the thing
does not exist. Re-fetch the URL directly before drawing any conclusion from
it.

## Rationalizations to Reject

- **"There are 200 changed functions, this patch is undiffable."** Most are
  compiler and layout noise. Sort by similarity and filter to logic changes; the
  security fix is usually one to a handful of functions.
- **"I diffed the MSU directly and got nonsense."** Windows ships deltas, not
  whole files. Reconstruct the full patched binary from the delta and your
  baseline before diffing.
- **"The function changed, so it's the vulnerability."** A change is a lead.
  Without a reachable path from untrusted input to the pre-patch code, you may be
  looking at hardening. Prove reachability before you claim a bug.
- **"The advisory says RCE, so this is the RCE."** Advisories are vague on
  purpose. Confirm the bug class from the added check, not from the marketing
  words in the bulletin.
- **"Same bug, so the old exploit works."** A fix can change adjacent code,
  offsets, and object layout. Re-confirm the primitive against the pre-patch
  build you actually have.

## References

- `analyzing-binaries` — understanding either binary on its own
- `exploiting-memory-corruption` — building the exploit from the recovered bug
- `reviewing-code-changes` — when you have source diffs rather than binaries
- `unpacking-protected-binaries` — when a binary must be unpacked before diffing
