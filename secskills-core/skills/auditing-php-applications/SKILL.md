---
name: auditing-php-applications
description: Audit PHP web application source for critical vulnerabilities using PHP's specific sink and footgun catalog — object injection via unserialize and phar:// POP chains, type-juggling and magic-hash auth bypass, LFI/RFI through php:// and phar:// wrappers, dynamic includes and extract()/superglobal trust, SQL injection in string-built and legacy mysql_* queries, command-execution sinks, and SSRF. Use when reviewing a PHP codebase, a WordPress/Magento/Laravel app, or a plugin for exploitable bugs. Defers general audit methodology to auditing-code-for-vulnerabilities.
verified: 2026-07-27
---

# Auditing PHP Applications

This is the PHP-specific layer on top of `auditing-code-for-vulnerabilities`.
Take the methodology from that skill — context → attack surface → bug-class
hunt → variant analysis → the four-question verification gate — and apply the
PHP sink catalog below to it. This skill exists because PHP has footguns no
language-agnostic methodology carries: features that turn a file read into
remote code execution, and comparison rules that turn `==` into an auth bypass.

The collection deliberately has no per-language audit skills except this one.
PHP earns the exception because it dominates the legacy-web and
WordPress/Magento space where critical bugs actually live, and because its
dynamic features fail in ways a reviewer must be primed for specifically.

## When to Use

- Reviewing a PHP codebase or plugin for exploitable vulnerabilities
- Auditing a WordPress, Magento, Joomla, or Laravel application's source
- Tracing a suspected RCE, LFI, SQLi, or object-injection path in PHP
- Deciding whether a `unserialize`, `include`, or `==` on user input is exploitable

## When NOT to Use

- **General audit methodology, or a non-PHP language** — use
  `auditing-code-for-vulnerabilities`; this skill assumes it
- **Finding a planted webshell or backdoor** rather than a vulnerability — use
  `hunting-web-backdoors`
- **Building the deserialization exploit chain** once you have the sink — use
  `exploiting-deserialization`
- **Black-box testing a running app** — use `testing-web-applications`
- **Reviewing only the diff of a change** — use `reviewing-code-changes`

## Sinks by Bug Class

Trace user input (superglobals, headers, uploaded filenames, DB values that
were once user input) to each of these. A sink is only a bug when a source
reaches it.

### Remote code execution

- **Direct eval sinks:** `eval`, `assert` (string arg, pre-8.0),
  `preg_replace` with `/e` (pre-7.0), `create_function` (pre-8.0),
  `mb_ereg_replace`/`mb_eregi_replace` with the `e` option.
- **Command execution:** `system`, `exec`, `passthru`, `shell_exec`, backticks,
  `proc_open`, `popen`, `pcntl_exec`. Watch `escapeshellarg` vs
  `escapeshellcmd` misuse — `escapeshellcmd` does **not** prevent argument
  injection.
- **Dynamic dispatch:** `$func()` where `$func` derives from input,
  `call_user_func`/`call_user_func_array`, `array_map`/`usort`/
  `preg_replace_callback` with a user-influenced callback.

### Object injection (the PHP-defining bug)

- `unserialize()` on any user-controlled data is object injection. Exploitation
  is a **POP chain**: existing classes with `__wakeup`, `__destruct`,
  `__toString`, or `__call` magic methods that do something dangerous when the
  object is materialized. The vulnerable file often contains no dangerous code
  at all — the gadget lives in a framework or dependency.
- **`phar://` is unserialize in disguise — but version-gated.** On **PHP
  before 8.0**, any file operation (`file_exists`, `fopen`, `include`,
  `getimagesize`, …) on a `phar://` path automatically deserializes the Phar's
  metadata, so a path-traversal or LFI that points a file function at an
  uploaded `.phar` (or any file carrying Phar metadata) is object injection
  with no `unserialize` call in sight. **PHP 8.0 removed that automatic
  unserialize** — only explicit `Phar::getMetadata()` deserializes now. So the
  bug is critical on the huge installed base of PHP 7.x and a non-issue on 8.x
  unless the code calls `getMetadata()` itself. Check the runtime version
  before ruling it in or out.
- Prefer `json_decode` in remediation; flag every `unserialize` on non-trusted
  data regardless of an obvious gadget — the gadget may arrive with the next
  dependency update.

### LFI / RFI and stream wrappers

- `include`, `require`, `include_once`, `require_once` with user input.
- **Wrappers that change everything:** `php://filter/...` (read source, and a
  known RCE chain via `convert.iconv`/compression filters),
  `php://input` (RFI-style body inclusion), `data://` (inline payload),
  `phar://` (object injection), `expect://`, `zip://`. `allow_url_include`
  being on turns LFI into remote RFI.
- File-read sinks (`file_get_contents`, `readfile`, `fopen`, `highlight_file`)
  with traversal give source and secret disclosure.

### SQL injection

- Legacy `mysql_query`/`mysqli_query` with string-concatenated input.
- `$wpdb->query("... $var ...")` **without** `$wpdb->prepare()` — a `->prepare`
  that is present but interpolates outside its placeholders is still injectable.
- PDO/mysqli used with string building instead of bound parameters. Placeholder
  usage on the *table/column* name (which cannot be bound) is a common real hole.

### Type juggling and magic-hash auth bypass

- **`==` and `!=` are loose.** `strcmp`/`hash_equals`/`===` are the safe forms.
  The classic bypass: `if (md5($input) == $stored)` where two inputs both hash
  to a `0e[0-9]+` "magic hash" compare equal, because two numeric strings
  compare as numbers (`0e123 == 0e456` → `0.0 == 0.0`).
- **Version matters and it is a trap.** In PHP 8.0 the number-vs-string rules
  changed: `0 == "foo"` was `true` in PHP 7 and is `false` in PHP 8, so a
  `in_array(0, $userStrings)` or `0 == $token` bypass that worked on PHP 7
  fails on PHP 8. **But the `0e` magic-hash bypass survives PHP 8**, because
  both sides are numeric strings and still compare as numbers. Check the target
  PHP version before ruling a juggling bug in or out.
- `strcmp($_GET['x'], $secret)` returned `NULL` (loosely `== 0`) when passed an
  array in PHP 7 — an auth bypass; in PHP 8 it throws a `TypeError`. Same code,
  different verdict by version.

### Superglobal trust and variable variables

- `extract($_GET/$_POST/$_REQUEST)` lets a request set arbitrary local
  variables — overwrites auth flags, config, anything not yet initialized.
- `$$var` / `${$key}` variable variables, `parse_str` without a result array
  (writes into scope), `import_request_variables` (removed 5.4) — all
  register_globals-flavoured variable injection.

### SSRF and file upload

- `file_get_contents`/`curl`/`fopen` on a user-supplied URL is SSRF — route the
  exploitation reasoning through `exploiting-ssrf`.
- Uploads: check the destination is outside the web root, the extension is not
  attacker-chosen (double extensions, `.phtml`, `.php5`, null bytes on old
  PHP), and the server will not execute the type. A validated MIME with an
  attacker-controlled extension in a web-served directory is RCE.

## Ecosystem Context

- **WordPress:** nonces are **CSRF** protection, not authorization — a valid
  nonce does not mean the user is allowed to act; look for the missing
  `current_user_can()` check. `$wpdb->prepare` is mandatory for interpolation.
  `unfiltered_html`, `edit_*` capabilities, and unauthenticated AJAX/REST
  (`wp_ajax_nopriv_*`, `permission_callback => '__return_true'`) are the usual
  holes.
- **Magento:** heavy `unserialize` history, layout-XML injection, and the admin
  path/patch level matter for known-CVE reachability.
- **Laravel:** mass assignment (`$fillable`/`$guarded`), Blade `{!! !!}`
  (unescaped) vs `{{ }}` (escaped), and a leaked `APP_KEY` enabling
  cookie/`decrypt` object injection.

## Verify Before You Report

Apply `auditing-code-for-vulnerabilities`' gate: trace the source to the sink,
confirm the path is reachable (auth, routing, and — critically — the **PHP
version** for juggling and removed-function bugs), and demonstrate impact
rather than asserting it. A `unserialize` with no reachable gadget, or a `/e`
regex on PHP 8, is a hardening note, not a critical finding — say which.

## Rationalizations to Reject

- *"There's no `unserialize`, so no object injection."* `phar://` reaches
  unserialize through ordinary file functions. Check every file operation whose
  path a user can influence.
- *"It uses `==`, that's fine for a hash check."* `==` on hashes is the
  magic-hash bypass. Only `hash_equals`/`===` are safe, and the bypass survives
  PHP 8.
- *"The comparison bug works, I confirmed it."* On which PHP version? `0 == "x"`
  and `strcmp(array)` flipped verdict at PHP 8.0. State the version.
- *"`prepare()` is called, so the query is safe."* Only for values inside
  placeholders. Interpolated table/column names and text spliced around the
  placeholders are still injectable.
- *"The nonce check passes, so it's authorized."* WordPress nonces are CSRF
  tokens. Authorization is a separate `current_user_can()` you must find.
- *"The upload validates the MIME type."* MIME is spoofable and irrelevant if
  the attacker controls the extension and the directory executes PHP.
- *"It's a framework class, the gadget isn't here."* POP-chain gadgets live in
  dependencies by design. The absence of dangerous code in the vulnerable file
  is normal, not exculpatory.

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

- `auditing-code-for-vulnerabilities` — the general methodology and gate this
  skill sits on top of
- `hunting-web-backdoors` — planted malice rather than vulnerabilities
- `exploiting-deserialization` — building the POP chain once you find the
  `unserialize`/`phar://` sink
- `exploiting-ssrf` — the exploitation side of a user-controlled URL fetch
- `testing-web-applications` — black-box testing of the running application
