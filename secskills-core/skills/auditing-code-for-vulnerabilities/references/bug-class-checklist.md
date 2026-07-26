# Bug Class Checklist by Language and Stack

Load this when you have mapped the attack surface and need per-language
hunting patterns. Each entry is a question to answer in the code, not a
pattern to grep blindly.

## C / C++

| Check | What to look for |
| --- | --- |
| Length arithmetic | `len - 1`, `size + offset`, `n * sizeof(x)` computed *before* the bounds check, or on a signed type |
| `memcpy` / `strcpy` family | Destination size derived from the source rather than the buffer |
| Integer conversion | `int` → `size_t`, truncation at `(uint16_t)`, `strlen` result compared to a signed value |
| Use-after-free | Frees on error paths, double-free in cleanup `goto` chains, freed pointer reused by a callback |
| Format strings | `printf(user_input)`, `syslog(fmt)` where `fmt` is not a literal |
| Uninitialized reads | Stack structs passed to a writer that returns early on error |
| `alloca` / VLA | Attacker-influenced stack allocation size |

```bash
rg -n 'memcpy|strcpy|sprintf|alloca|\[[a-z_]+\]\s*;' --type c
rg -n 'malloc\(.*\*|calloc\(.*\+' --type c   # arithmetic inside allocation size
```

## Rust

- Every `unsafe` block: what invariant does it assume, and who upholds it?
- `from_raw_parts`, `transmute`, `get_unchecked` — the classic three.
- `unwrap()`/`expect()` on attacker-controlled input is a DoS, not a nit.
- Integer overflow is only checked in debug builds; look for `as` casts.
- `Deserialize` impls that skip validation that the constructor enforces.

```bash
rg -n 'unsafe\s*\{' -A5 && cargo geiger
```

## Go

- `err` assigned and ignored (`_ =`), especially around auth and crypto calls.
- Goroutines sharing a map or struct without a mutex; run `go test -race`.
- `fmt.Sprintf` building SQL, shell, or URLs.
- `http.Client` without a `Timeout` (resource exhaustion).
- `crypto/rand` vs `math/rand` — the latter for tokens is a real finding.
- Slice aliasing after `append`, and `defer` inside a loop.

```bash
rg -n 'math/rand|InsecureSkipVerify|fmt\.Sprintf\(".*(SELECT|INSERT|http)' --type go
gosec ./... && go vet ./...
```

## Python

- `pickle`, `marshal`, `yaml.load` without `SafeLoader`, `jsonpickle`.
- `subprocess(..., shell=True)` and `os.system` with any interpolation.
- Mutable default arguments holding per-request state across requests.
- ORM escapes: `.raw()`, `.extra()`, `RawSQL`, f-strings inside `execute()`.
- Django/Flask: `DEBUG=True`, `SECRET_KEY` in source, `@csrf_exempt`.
- `assert` used for an access check (stripped under `-O`).
- Path handling: `os.path.join` with an absolute attacker segment discards the prefix.

```bash
rg -n 'pickle\.loads|yaml\.load\((?!.*SafeLoader)|shell=True|csrf_exempt|\.raw\(|assert .*(admin|auth|perm)'
bandit -r . -ll
```

## JavaScript / TypeScript / Node

- Prototype pollution: recursive merge, `Object.assign` on parsed JSON, `lodash.merge` on user input.
- `child_process.exec` vs `execFile`; template literals inside `exec`.
- `res.redirect(req.query.next)` — open redirect and SSRF pivot.
- JWT: `algorithms` unset, `jwt.decode` used instead of `jwt.verify`.
- `dangerouslySetInnerHTML`, `v-html`, `innerHTML =`, `document.write`.
- ReDoS: nested quantifiers on user-supplied input.
- Missing `SameSite`/`httpOnly`/`secure` on session cookies.

```bash
rg -n 'dangerouslySetInnerHTML|innerHTML\s*=|child_process\.exec\(|jwt\.decode\(|merge\(.*req\.'
```

## Java / Kotlin

- `ObjectInputStream.readObject` on any untrusted stream.
- XXE: `DocumentBuilderFactory` / `SAXParserFactory` without
  `setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`.
- Expression-language injection: SpEL, OGNL, `MessageFormat` with user data.
- `Runtime.getRuntime().exec` with concatenation.
- Spring: `@PreAuthorize` on the interface but not the implementation; missing
  method-level checks when `@EnableGlobalMethodSecurity` is absent.
- Path traversal via `new File(base, userPath)`.

## PHP

- `include`/`require` with any dynamic segment (LFI → RCE via log or session).
- `unserialize` on user data plus a gadget chain in a loaded library.
- `==` on hashes (type juggling); use `hash_equals`.
- `extract()`, `$$var`, and `register_globals`-style patterns.
- `move_uploaded_file` with an attacker-controlled extension.

## Web framework cross-cutting

| Class | Question |
| --- | --- |
| IDOR / BOLA | Does the query filter by the caller's tenant, or only by ID? |
| Mass assignment | Is the model bound from the whole request body? Which fields are protected? |
| SSRF | Does any server-side fetch take a user URL? Is the resolved IP re-checked after redirect? |
| Race conditions | Is any balance, quota, coupon, or invite consumed without a transaction or lock? |
| File upload | Is the type decided by extension, `Content-Type`, or content? Where is it stored, and is that path served? |
| CSRF | State-changing `GET`s? Token bound to the session? `SameSite` set? |
| Rate limiting | Is auth, password reset, and OTP verification limited per account *and* per IP? |
| Logging | Are secrets, tokens, or PII logged? Is log output attacker-controlled (log injection)? |

## Infrastructure as code

- Terraform: `0.0.0.0/0` ingress, public S3/GCS buckets, unencrypted volumes,
  IAM policies with `"Action": "*"`.
- Kubernetes: `privileged: true`, `hostPID`, `hostNetwork`, missing
  `securityContext`, secrets mounted as env vars, default ServiceAccount tokens.
- GitHub Actions: `pull_request_target` with a checkout of the PR head,
  unpinned third-party actions, `${{ github.event.* }}` interpolated into `run:`.
  See `auditing-supply-chain`.

```bash
checkov -d . --compact
tfsec . && trivy config .
```

## Bug-class-to-CWE quick map

| Finding | CWE |
| --- | --- |
| SQL injection | CWE-89 |
| Command injection | CWE-78 |
| Path traversal | CWE-22 |
| SSRF | CWE-918 |
| Broken object level authorization | CWE-639 / CWE-862 |
| Deserialization | CWE-502 |
| Buffer overflow | CWE-787 / CWE-125 |
| Use after free | CWE-416 |
| Race condition (TOCTOU) | CWE-367 |
| Hardcoded credentials | CWE-798 |
| Weak randomness | CWE-338 |
| XXE | CWE-611 |
| Prototype pollution | CWE-1321 |
