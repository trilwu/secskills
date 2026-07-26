---
name: reviewing-cryptography
description: Review cryptographic implementations and protocol usage for misuse — weak primitives, nonce and IV handling, key management, authentication of ciphertext, randomness, timing side channels, TLS and JWT configuration, and password storage. Use when auditing code that encrypts, signs, hashes, or authenticates, or when assessing TLS and token configurations.
---

# Reviewing Cryptography

Almost no real system is broken by cryptanalysis. They are broken by misuse:
a reused nonce, unauthenticated ciphertext, a comparison that returns early,
a key checked into git. Review for misuse, and leave primitive design to
cryptographers.

## When to Use

- Auditing code that encrypts, decrypts, signs, verifies, or hashes
- Reviewing key management, rotation, and storage
- Assessing TLS/mTLS configuration and certificate validation
- Reviewing JWT, session token, and API signature schemes
- Checking password and secret storage
- Evaluating randomness quality for security-relevant values

## When NOT to Use

- **Designing a new primitive or protocol** — that needs a cryptographer and
  formal review, not a code audit
- **Breaking cryptography in a CTF** — different discipline; use
  `solving`-oriented offensive skills and known-attack tooling
- **General code review** — use `auditing-code-for-vulnerabilities`
- **Password cracking** — use `cracking-passwords`

## The Misuse Checklist

Work through these in order. Each has caught real production breaks.

### 1. Is the ciphertext authenticated?

Encryption without authentication is the single most common serious finding.
CBC or CTR without a MAC means an attacker can modify plaintext — and with a
decryption oracle, recover it (padding oracle).

```
Good:  AES-GCM, ChaCha20-Poly1305, AES-CBC + HMAC (encrypt-then-MAC)
Bad:   AES-CBC alone, AES-ECB (ever), CTR without a MAC, MAC-then-encrypt
```

```bash
rg -n 'AES/ECB|AES\.MODE_ECB|CipherMode\.ECB|"AES"\)' -i
rg -n 'AES/CBC/PKCS5Padding|MODE_CBC|createCipheriv\(.*cbc' -i
```

If you see CBC, find the MAC. If there is no MAC, that is a finding regardless
of how the ciphertext is transported.

### 2. Nonce and IV handling

| Mode | Rule | Failure |
| --- | --- | --- |
| GCM / ChaCha20-Poly1305 | Never reuse a (key, nonce) pair | Catastrophic: reveals the auth key, forgery becomes trivial |
| CBC | IV must be unpredictable and random per message | Chosen-plaintext attacks (BEAST-class) |
| CTR | Never reuse a counter with the same key | Keystream reuse; XOR of plaintexts |

```bash
# The classic bug: a fixed or zero IV
rg -n 'iv\s*=\s*(b?["\x27]0|new byte\[\d+\]|bytes\(\d+\)|\[0\]\s*\*)' -i
rg -n 'IvParameterSpec\(new byte\[16\]\)|createCipheriv\([^,]+,[^,]+,\s*["\x27]'
```

Random 96-bit nonces for GCM are safe up to roughly 2^32 messages per key.
A counter-based nonce is safer, but only if the counter state genuinely
survives restarts and is not duplicated across instances. Ask where the
counter is persisted; "in memory" plus horizontal scaling means reuse.

### 3. Key management

- Where does the key come from? Hardcoded, env var, KMS/HSM, derived?
- Hardcoded keys, keys in source, keys in config committed to the repo, keys
  in container images, keys in CI logs — check all of these.
- Is a key used for exactly one purpose? Key reuse across encryption and
  signing, or across tenants, is a finding.
- Is there a rotation path at all? A system that cannot rotate has no response
  to compromise.
- Derived keys: is a proper KDF used (HKDF for key material, Argon2id/scrypt/
  PBKDF2 for passwords)? A raw SHA-256 of a password is not a KDF.

```bash
rg -n 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|-----BEGIN'
rg -n '(secret|api[_-]?key|password|token)\s*[:=]\s*["\x27][A-Za-z0-9/+=]{16,}' -i
gitleaks detect --source . --redact      # history matters more than the tree
```

### 4. Password storage

```
Correct:   Argon2id (preferred), scrypt, bcrypt, PBKDF2-HMAC-SHA256 with a
           high iteration count — each with a per-user random salt
Wrong:     MD5, SHA-1, SHA-256, SHA-512 (raw or salted), any unsalted hash,
           encryption instead of hashing, a "pepper" as the only defense
```

Check the work factor against current guidance, not the value that was
adequate when the code was written. And check that the verification path uses
the library's constant-time verify function rather than comparing strings.

### 5. Randomness

Security-relevant values — tokens, session IDs, nonces, salts, password reset
codes, IVs — must come from a CSPRNG.

```bash
rg -n 'math/rand|Math\.random\(\)|random\.random\(|rand\(\)|mt_rand|Random\(\)' 
# Correct: crypto/rand, secrets.token_bytes, window.crypto.getRandomValues,
#          SecureRandom, os.urandom, RandomNumberGenerator
```

Also check: seeding with a timestamp or PID, UUIDv1/v4-from-a-weak-source used
as a secret, and predictable sequential IDs used where unguessability is
assumed.

### 6. Timing side channels

Any comparison of a secret must be constant time: MACs, tokens, API
signatures, password hashes, OTPs.

```bash
rg -n 'hmac.*==|token\s*==|signature\s*==|\.equals\(.*(hmac|token|sig)' -i
# Correct: hmac.compare_digest, crypto.timingSafeEqual, subtle.ConstantTimeCompare,
#          MessageDigest.isEqual, hash_equals
```

Early-return string comparison of an HMAC is a practical remote attack, not a
theoretical one.

### 7. Signature verification

- Is the signature actually verified, or merely parsed?
- Is the algorithm taken from the message? (JWT `alg` confusion: `none`, and
  RS256→HS256 where the public key becomes the HMAC key.)
- Is the key selected by an identifier the attacker controls (`kid`, `jku`,
  `x5u`)? Those fields are attacker input; treat them as such.
- Are claims validated after signature verification: `exp`, `nbf`, `iss`,
  `aud`, and — critically — the subject's current authorization?

```bash
rg -n 'jwt\.decode\(|verify\s*[:=]\s*(False|false)|algorithms\s*=\s*\[?["\x27]?none' -i
rg -n 'InsecureSkipVerify|verify\s*=\s*False|CURLOPT_SSL_VERIFYPEER.*0|rejectUnauthorized:\s*false'
```

### 8. TLS configuration

```bash
# Server side
testssl.sh --severity MEDIUM https://target
sslyze --regular target:443
nmap --script ssl-enum-ciphers -p 443 target

# Look for: TLS < 1.2, RC4/3DES/NULL/EXPORT ciphers, no forward secrecy,
# weak DH params, expired or misissued certs, missing HSTS
```

Client side is more often wrong than server side. Check that certificate
verification is enabled, that hostname verification is on (it is separate
from chain verification in several libraries), and that custom trust stores
are not silently accepting everything. A custom `TrustManager` that returns
without throwing is the Java idiom for "no TLS at all."

### 9. Post-quantum posture

For anything with a long confidentiality lifetime, note harvest-now-decrypt
later exposure and whether a hybrid key exchange (e.g. X25519 + ML-KEM) is
available in the stack. This is a roadmap finding, not usually an urgent one —
but say so explicitly rather than omitting it.

## Protocol-Level Questions

Beyond primitives, ask:

- **Replay**: is there a nonce, timestamp, or sequence number, and is it
  actually checked and stored?
- **Binding**: is the signature bound to the whole message, including the
  recipient and context? Signature-stripping and cross-protocol reuse come
  from under-scoped signing.
- **Downgrade**: can a client or server be negotiated to a weaker mode?
- **Oracles**: does the error handling distinguish "bad padding" from "bad
  MAC", or decryption failure from authorization failure? Any observable
  difference — including timing and response size — is an oracle.
- **Canonicalization**: if a signature covers a serialized structure, can the
  same structure serialize two ways? JSON and XML signature schemes break here
  routinely.

## Rationalizations to Reject

- *"It's encrypted."* Encrypted is not authenticated, and not authorized.
- *"We use AES-256, so it's strong."* Key size is almost never the weak link.
- *"The IV is random enough."* Show where it is generated and from what.
- *"Timing attacks aren't practical over a network."* They are, and have been
  demonstrated repeatedly across the internet.
- *"We rolled our own because the library was awkward."* Custom crypto is a
  finding on its own. Name the library that should be used instead.
- *"The key is in an environment variable, not the code."* Better, but check
  where the env var is set, who can read the process environment, and whether
  it appears in logs, crash dumps, or the container image.
- *"Certificate pinning is too much hassle."* Fine — but then say so as an
  accepted risk, do not disable verification instead.
- *"It's internal traffic."* Internal networks are where lateral movement
  happens.

## Deliverable

For each finding: the primitive or protocol involved, the specific misuse, the
concrete attack it enables (not "weak crypto"), the affected data and its
confidentiality lifetime, and the specific correct construction — named
library, named mode, named parameters. Cryptography findings that recommend
"use strong encryption" do not get fixed.

## References

- `auditing-code-for-vulnerabilities` — the surrounding code review
- `cracking-passwords` — offensive side of weak password storage
- `testing-apis` — token and signature handling at the API layer
- Libraries to recommend: libsodium/NaCl, Google Tink, `age`, platform AEAD APIs
- `testssl.sh`, `sslyze`, `cryptography` (Python) audit APIs, `cargo-crev`
