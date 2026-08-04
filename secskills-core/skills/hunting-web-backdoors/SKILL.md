---
name: hunting-web-backdoors
description: Hunt planted webshells and backdoors across a web source tree — PHP first (also JSP, ASP, Node) — triaging a directory at scale, statically decoding obfuscation layers without ever executing the payload, finding append-infections and fake plugins, and treating known shell families as leads rather than verdicts. Use when a web server is suspected compromised, cleaning a hacked WordPress/Magento/CMS site, vetting a downloaded PHP codebase or plugin for hidden malicious code, or when a file contains eval on decoded input.
verified: 2026-07-27
---

# Hunting Web Backdoors

This is not a vulnerability audit. You are looking for code an attacker
**already planted** — a webshell, a one-line eval backdoor, a fake plugin, a
malicious line appended to a legitimate file. The weakness that let them in is
`auditing-php-applications`' job; this skill finds what they left behind.

Two things make it hard. The malicious code is deliberately hidden — obfuscated,
split, or buried in a tree of thousands of legitimate files — so a naive grep
misses it. And the tells (`eval`, `base64_decode`, dynamic calls) appear in
plenty of benign code, so a naive grep also drowns you in false positives. The
work is the discrimination.

## When to Use

- A web server is suspected or confirmed compromised and you need every shell
- Cleaning a hacked WordPress, Magento, Joomla, or custom PHP site
- Vetting a downloaded plugin, theme, or codebase before deploying it
- A file contains `eval`, `assert`, or `system` on decoded or request-derived input
- Triaging a web root full of unfamiliar PHP for planted malice

## When NOT to Use

- **Finding the vulnerability that allowed the upload** — use
  `auditing-php-applications`
- **Deep single-sample analysis** (a specific shell you want to fully reverse,
  its C2, its capabilities) — use `analyzing-malware`
- **The broader incident** (scoping, timeline, containment) — use
  `responding-to-incidents`; this skill is the source-tree sweep within it
- **Malicious dependencies / package install scripts** — use
  `auditing-supply-chain`
- **Host-level persistence** (cron, systemd, LD_PRELOAD) — use
  `analyzing-linux-persistence`

## Never Execute to Deobfuscate

The single rule that must not bend: **the obfuscated code is the payload.** Do
not run it, do not "just let PHP decode it," do not replace `eval(` with
`echo(` and execute the file, do not paste it into an online sandbox that runs
it. Deobfuscation is a **static** transformation:

- Decode the layers by hand or with a decode-only tool (`base64_decode`,
  `gzinflate`, `gzuncompress`, `str_rot13`, hex/`\xNN`, `strrev`) applied as
  string operations, not as executed PHP.
- If you must automate, use a de-obfuscator that decodes without executing
  (UnPHP's decoder, a Python reimplementation of the decode chain) — never the
  PHP interpreter on the sample.
- Replacing the final `eval(` with `file_put_contents('out.php', ...)` and
  running it *is* executing the payload if any prior layer has side effects.
  Decode statically, then read.

"Most webshells are three or four layers of encoding around ten lines of logic"
— peel to the logic, do not detonate the wrapper.

## Triage a Directory at Scale

You cannot read every file. Rank candidates by cheap signals, then read the
top of the list:

```bash
# 1. PHP where PHP should not be — uploads, cache, images, media dirs
find wp-content/uploads -name '*.php' -o -name '*.php[0-9]' -o -name '*.phtml' 2>/dev/null

# 2. Recently modified, clustered in time (attackers touch many files at once)
find . -name '*.php' -newermt '2026-07-01' -printf '%T+ %p\n' | sort

# 3. High entropy / long single lines — the shape of packed obfuscation
find . -name '*.php' -exec awk 'length>1000{print FILENAME": "length; nextfile}' {} \;

# 4. The dangerous-sink grep — leads, NOT verdicts (see the FP problem below)
grep -rnE '\b(eval|assert|system|passthru|shell_exec|proc_open|popen|create_function)\s*\(' --include='*.php' .
grep -rnE '(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin)\s*\(' --include='*.php' .

# 5. Request-driven code execution — the webshell core
grep -rnE '\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[[^]]*\]\s*\(' --include='*.php' .
grep -rnE '(eval|assert|system|passthru)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)' --include='*.php' .
```

The most reliable single lead is **variable execution of request data** —
`$_POST['x']()`, `ev[a]l($_GET[...])`, `assert($_REQUEST[...])`,
`call_user_func($_GET['f'], ...)`. Legitimate code almost never dispatches a
function name straight from a superglobal.

## The Grep Is Not Clean Just Because It Is Empty

A source tree that returns nothing for `grep eval` can still be backdoored.
Attackers defeat the obvious grep deliberately:

- **Concatenation:** `$a='ev'.'al'; $a($code);` or `('e'.'v'.'a'.'l')(...)`.
- **Variable variables / indirection:** `$f='system'; $f($_GET['c']);`,
  `${'_'.'GET'}`, `$$x`.
- **Char/hex/octal escapes:** `"\x65\x76\x61\x6c"` is `eval`;
  `chr(101).chr(118)...`.
- **Callback sinks:** `array_map`, `array_filter`, `usort`,
  `preg_replace_callback`, `register_shutdown_function`,
  `ob_start` with a user-controlled callback.
- **String-eval that is not `eval`:** `assert($str)` (pre-8.0),
  `preg_replace('/./e', $str, ...)` (pre-7.0), `create_function('', $str)`
  (pre-8.0), `mb_ereg_replace` with `e`.
- **Comment and whitespace insertion** between token pieces to break naive
  regex.

So grep is a *lead generator*, not a coverage guarantee. When grep is empty and
you still suspect infection, fall back to: entropy/long-line ranking, mtime
clustering, and diffing against a known-good copy (below).

## Append-Infections Are the Ones You Miss

The hardest infection is a backdoor **appended to or inserted into a legitimate
file** — `index.php`, `wp-config.php`, a theme's `functions.php`, `vendor/`
autoloaders. The file is 99% real, so it does not stand out by name, location,
or entropy overall. Find these by comparison, not by inspection:

```bash
# Diff the tree against a pristine copy of the same CMS/plugin version
# (download the exact version from wordpress.org / the vendor)
diff -rq ./site /known-good/wordpress-6.x/

# WordPress core/plugin integrity via checksums
wp core verify-checksums; wp plugin verify-checksums --all

# git/composer/npm: what changed vs the committed/locked state
git status --porcelain; git diff
```

If you have no known-good baseline, the tells are: code *after* the closing
`?>` of an otherwise-normal file, a lone `eval`/`base64_decode` line wedged at
the top of a config file, or a `<?php ... ?>` block whose style clashes with
the surrounding file.

## Version-Gated Tells Date the Code

The presence of a removed language feature tells you something:

- `preg_replace` with the `/e` modifier — **removed in PHP 7.0**. Its presence
  means the backdoor targets (or predates) PHP 5.x.
- `create_function()` and string-argument `assert()` as code execution —
  **removed in PHP 8.0**. Common in older shells; on a PHP 8 server they would
  fault, which is itself a signal about when the code was planted.

## Known Families Are Leads, Not Verdicts

Fingerprints speed triage but do not replace reading the code:

> IOC strings in this section are bracket-broken — `ev[a]l` is `eval`,
> `ass[e]rt` is `assert`. Written literally they match `Backdoor:PHP/Chopper`
> and this file, a *defensive* hunting skill, gets quarantined on download.
> The grep patterns above are intact and safe to copy. See "Antivirus false
> positives" in the repo README.

- **China Chopper** — a *one-liner*: `<?php @ev[a]l($_POST['pass']);?>` (or
  `assert`), often under 30 bytes. Tiny, so easy to miss and easy to append.
- **WSO, b374k, c99, r57, indoxploit** — full-featured panels; grep their
  banner strings, characteristic function names, or auth-cookie names as leads.
- **Weevely** — generates obfuscated, password-gated shells that change per
  build; signature matching is weak, so rely on the request-driven-execution
  and obfuscation signals instead.

A signature hit confirms *a* shell. It does not confirm you found them all —
attackers plant several, and the second one rarely matches the first's family.

## When You Confirm One, Assume More

1. **Preserve before you delete.** A confirmed shell is evidence — copy it
   (hash it) to a holding location before removing it, per
   `responding-to-incidents`. Deletion alone loses the timeline and, if you
   miss the entry point, the attacker re-plants within hours.
2. **Find the entry point.** A shell got there somehow — a vulnerable upload,
   a known-CVE plugin, stolen credentials. Hand that to
   `auditing-php-applications` (source) or `responding-to-incidents`
   (logs); a cleaned site with the hole still open is re-infected by morning.
3. **Keep hunting.** One shell found is a reason to raise suspicion of the
   whole tree, not to close the case. Re-run the sweep after removing the
   obvious one.

## Rationalizations to Reject

- *"grep for eval came back clean, so the tree is clean."* Concatenation, hex
  escapes, and callback sinks all evade it. Empty grep is not coverage — fall
  back to entropy, mtime, and diff-against-known-good.
- *"I'll just run it to see what it decodes to."* That is executing the
  payload. Decode statically, always.
- *"It uses `eval`, so it's a backdoor."* Templating engines, caches, and
  frameworks use `eval` legitimately. The tell is `eval` on *decoded or
  request-derived* input, not `eval` itself.
- *"It's heavily obfuscated, so it's malicious."* Commercial plugins ship
  obfuscated (ionCube, Zend Guard, licensing). Obfuscation raises suspicion;
  it does not convict. Decode and read the logic.
- *"I found the shell and deleted it, done."* You found *a* shell. Preserve it,
  find the entry point, and re-sweep — attackers plant redundancy.
- *"The file is a core CMS file, it must be safe."* Append-infections live in
  exactly those files precisely because you assume that. Verify by checksum.
- *"No known-shell signature matched."* Weevely and custom shells match
  nothing. Signatures are leads; behaviour (request-driven execution,
  obfuscation) is the evidence.

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

## References

- `auditing-php-applications` — the vulnerability that let the shell in
- `analyzing-malware` — deep reverse of a single recovered shell, its C2 and
  capabilities
- `responding-to-incidents` — evidence handling, scoping, and the wider IR this
  sweep sits inside
- `analyzing-linux-persistence` — host-level persistence beyond the web root
- `writing-yara-rules` — turning a confirmed family into a reusable signature
