---
name: attacking-graphql
description: Test GraphQL APIs — introspection and schema recovery when introspection is disabled, field suggestion abuse, batching and alias-based rate limit bypass, query depth and complexity denial of service, authorization gaps per field and per resolver, and mutation abuse. Use when a target exposes /graphql, /v1/graphql, or /api/graphql, when requests contain a query or mutation body, or when responses carry a data and errors envelope.
---

# Attacking GraphQL

GraphQL moves authorization from routes to resolvers, and most teams do not
move their access control with it. The REST habit of protecting `/admin/*` has
no equivalent when every operation arrives at one endpoint — so the recurring
finding is not an exotic GraphQL bug, it is an ordinary authorization failure
on a field nobody thought to guard.

## When to Use

- The target exposes `/graphql`, `/graphiql`, `/v1/graphql`, `/api/graphql`
- Request bodies contain `query`, `mutation`, `subscription`, or `operationName`
- Responses have the `{"data": ..., "errors": [...]}` envelope
- A mobile or SPA client posts GraphQL to a backend
- You need to map an API whose schema you do not have

## When NOT to Use

- **REST or gRPC** — use `testing-apis` or `attacking-grpc-protobuf`
- **Source code available** — use `auditing-code-for-vulnerabilities`; read the
  resolvers, which is faster and more complete
- **The web app around it** — use `testing-web-applications`
- **Building a denial-of-service against production** — model the risk, prove it
  minimally, and get explicit authorization before any load

## Recover the Schema

```bash
# Standard introspection
curl -s https://target/graphql -H 'Content-Type: application/json' \
  -d '{"query":"query{__schema{types{name fields{name args{name type{name}}}}}}"}' | jq .

# Tooling that renders it usefully
graphql-cop -t https://target/graphql
clairvoyance https://target/graphql -o schema.json     # works WITHOUT introspection
graphw00f -t https://target/graphql                    # fingerprint the engine
```

**When introspection is disabled, the schema is usually still recoverable.**
Most engines return "did you mean" suggestions on a misspelled field, which
leaks valid names one character class at a time. `clairvoyance` automates
exactly this.

```bash
# Field suggestion leak — the response names fields you did not know
curl -s https://target/graphql -d '{"query":"{ userr { id } }"}' -H 'Content-Type: application/json'
# → "Cannot query field \"userr\" on type \"Query\". Did you mean \"user\"?"
```

Other schema sources: the client bundle (queries are usually inlined in the JS),
a `.graphql` file served by mistake, persisted-query manifests, and Apollo
Studio or similar tooling left public.

**Fingerprint the engine** — behaviour differs materially. Apollo, graphql-js,
Hasura, graphene, gqlgen, and HotChocolate each have distinct defaults for
batching, suggestions, depth limits, and error verbosity. `graphw00f` names it.

## Authorization Is the Main Event

Test authorization **per field and per resolver**, not per endpoint. A schema
where `user(id:)` is guarded but `user { organization { members { email } } }`
is not is the standard finding.

```graphql
# 1. Object-level: request another tenant's or user's object by ID
query { user(id: "other-user-id") { id email phone } }

# 2. Field-level: the object is yours, but a field should not be exposed
query { me { id email passwordHash internalNotes stripeCustomerId } }

# 3. Traversal: reach a protected object through an unguarded edge
query { post(id: 1) { author { email resetToken orders { total } } } }

# 4. Mutations: the usual suspects, called directly
mutation { updateUser(id: "other", input: {role: ADMIN}) { id role } }
mutation { deleteAccount(id: "other") { success } }
```

**Traversal through relationships is the highest-yield test.** Developers guard
the entry points they think about; nested edges inherit whatever the parent
resolver allowed, and often that is nothing. Enumerate the schema's edges and
walk from any object you legitimately own toward objects you do not.

Repeat every test at each privilege level you have: anonymous, low-privilege
user, and a second tenant's user.

## Batching and Alias Abuse

One HTTP request can carry many operations, which defeats per-request rate
limiting — the classic 2FA and password brute-force bypass.

```graphql
# Aliases: N attempts, one request
{
  a1: login(user:"admin", pass:"1234") { token }
  a2: login(user:"admin", pass:"1235") { token }
  a3: login(user:"admin", pass:"1236") { token }
}
```

```json
[ {"query":"{ user(id:1){email} }"},
  {"query":"{ user(id:2){email} }"},
  {"query":"{ user(id:3){email} }"} ]
```

Array batching is supported by default in several engines. Test both forms;
they are often limited differently, and rate limiting applied at the HTTP layer
sees one request either way.

## Denial of Service by Query Shape

```graphql
# Depth: cyclic relationships nested repeatedly
{ user { posts { author { posts { author { posts { id } } } } } } }

# Breadth: aliases multiply one expensive resolver
{ a: search(q:"x"){id} b: search(q:"x"){id} c: search(q:"x"){id} ... }

# Field duplication amplifies without depth
{ user { id id id id id id ... } }
```

Check for: a depth limit, a complexity/cost limit, a timeout, a node limit on
pagination, and whether the engine batches N+1 resolver calls or issues one
query per node. **Prove the risk with a small, bounded query** — measure the
response-time gradient across depths rather than actually exhausting the
service. A single 8-level query that takes 30 seconds when a 3-level one takes
30 milliseconds is the evidence; you do not need to take the API down.

## Injection Through Resolvers

Resolvers reach databases the same as any other handler, so the classic classes
apply — with the twist that arguments are strongly typed, which people mistake
for validation.

```graphql
{ user(filter: "1' OR '1'='1") { id } }                 # SQL/NoSQL injection
{ users(where: {email: {_ilike: "%"}}) { email } }       # Hasura-style filter abuse
{ file(path: "../../etc/passwd") { contents } }          # traversal
```

Hasura and similar auto-generated APIs deserve specific attention: they expose
rich `where` filters directly to the client, so a permissive row-level-security
configuration means the filter language itself becomes the vulnerability.

## Other Checks Worth Running

- **CSRF via `GET` or form-encoded queries.** If the endpoint accepts
  `?query=mutation{...}` or `application/x-www-form-urlencoded`, mutations are
  reachable cross-origin without a preflight.
- **Introspection in production** — low severity alone, but it hands over the map.
- **Verbose errors** leaking stack traces, resolver names, and internal paths.
- **Subscriptions over WebSocket** — authorization is frequently checked at
  connect and never again, so a long-lived subscription survives logout and
  privilege changes.
- **Persisted queries** — check whether the server still accepts arbitrary
  queries when the client only sends hashes; an APQ implementation that falls
  back to arbitrary queries provides no protection.
- **File uploads** via the multipart spec, which is a separate parser.

## Rationalizations to Reject

- *"Introspection is disabled, so the schema is protected."* Suggestions leak
  it, and the client bundle contains it.
- *"The gateway rate-limits the endpoint."* It counts HTTP requests. Aliases
  and batching put a thousand operations in one.
- *"Arguments are typed, so injection is impossible."* Types constrain shape,
  not content. A `String` still reaches the database.
- *"That field is only used by the admin UI."* The schema exposes it to
  everyone; the UI is not an access control.
- *"The top-level query checks authorization."* Test the nested edges. That is
  where it fails.
- *"Depth limiting is in place."* Check breadth and aliases too.
- *"I'll prove the DoS by taking it down."* Prove the gradient. Ask before load.

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills-core/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Initial Access** (TA0001)

- [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application — see also `testing-web-applications`, `testing-apis`, `enumerating-network-services`, `attacking-grpc-protobuf`, `exploiting-deserialization`, `exploiting-ssrf`, `exploiting-xxe`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- `testing-apis` — the general API methodology this specializes
- `auditing-code-for-vulnerabilities` — resolver-level review when source exists
- `testing-web-applications` — the app around the endpoint
- `reporting-security-findings` — severity for authorization findings
- graphw00f, clairvoyance, graphql-cop, InQL (Burp), Altair/GraphiQL
