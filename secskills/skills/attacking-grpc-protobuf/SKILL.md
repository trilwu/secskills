---
name: attacking-grpc-protobuf
description: Test gRPC and Protocol Buffers services — recovering .proto definitions from server reflection or compiled descriptors, calling methods with grpcurl and grpcui, intercepting HTTP/2 and gRPC-Web traffic, and fuzzing unknown message schemas with protobuf-inspector. Use when a target speaks gRPC, HTTP/2 with application/grpc, or when a request body is opaque binary protobuf rather than JSON.
---

# Attacking gRPC and Protobuf Services

gRPC breaks the tooling assumption that a request is readable text over
HTTP/1.1. Burp shows a binary blob or nothing at all, and without the schema
you cannot even name the methods. Recover the schema and it becomes an
ordinary API test — with the twist that gRPC services are frequently internal
services newly exposed, which means their authorization is often weaker than
the REST API in front of them.

## When to Use

- Traffic uses HTTP/2 with `content-type: application/grpc`
- A request or response body is opaque binary with no JSON structure
- The app is a mobile or desktop client talking to a backend over protobuf
- You find `.proto` files, `*_pb2.py`, `*.pb.go`, or `grpc` in a codebase
- `application/grpc-web` or `application/grpc-web+proto` appears in a browser app

## When NOT to Use

- **REST or GraphQL** — use `testing-apis`
- **The proxy cannot see the traffic at all** on mobile — use
  `bypassing-mobile-pinning`; gRPC clients often ignore system proxy settings
- **Source code is available** — use `auditing-code-for-vulnerabilities`, and
  read the `.proto` files directly
- **Binary protocol that is not protobuf** — use `analyzing-binaries`

## Recover the Schema

Everything depends on this. Four routes, in order of cost.

**1. Server reflection.** Many services ship it enabled, often unintentionally.

```bash
grpcurl -plaintext target:50051 list
grpcurl -plaintext target:50051 list package.ServiceName
grpcurl -plaintext target:50051 describe package.ServiceName.MethodName
grpcurl -plaintext target:50051 describe package.RequestMessage

# TLS
grpcurl target:443 list
grpcurl -insecure target:443 list          # self-signed / proxy in path
```

Reflection enabled on an internet-facing service is itself worth reporting —
it is the gRPC equivalent of GraphQL introspection in production.

**2. Descriptors compiled into a client.** Protobuf embeds a serialized
`FileDescriptorProto` in generated code, so the schema is recoverable from any
client binary.

```bash
# Mobile/desktop client: find and extract descriptor blobs
rg -a -o 'google/protobuf/descriptor.proto|\.proto' target_binary | head
# protobuf-inspector and protod can reconstruct .proto from embedded descriptors
protod target_binary -o ./protos

# JS/web clients: the descriptor is usually in the bundle as base64 or an array
rg -n 'grpc-web|serializeBinary|deserializeBinary' bundle.js | head
```

**3. From the app's source or artifacts.** `.proto` files in a repo, a Swagger
gateway config, or generated stubs in a package.

**4. Field-by-field inference.** When you have neither, decode the wire format
directly. Protobuf is self-describing enough to recover structure without the
schema:

```bash
protoc --decode_raw < message.bin
protobuf-inspector < message.bin
# Output: field numbers, wire types, and values — enough to fuzz and to
# recognize strings, nested messages, and integers
```

You lose field *names* but keep field *numbers*, which is all the wire format
needs. That is sufficient to modify values and to add fields the client never
sends.

## Calling Methods

```bash
# With reflection
grpcurl -plaintext -d '{"user_id": 1}' target:50051 package.Service/GetUser

# With a local .proto
grpcurl -import-path ./protos -proto api.proto \
        -d '{"user_id": 1}' target:50051 package.Service/GetUser

# Interactive browser UI, good for exploring
grpcui -plaintext target:50051

# Headers, including auth
grpcurl -H 'authorization: Bearer eyJ...' -plaintext target:50051 package.Service/List
```

For streaming methods, `grpcurl` accepts newline-delimited JSON on stdin for
client streaming, and prints each message for server streaming. Streaming
endpoints are frequently less-tested than unary ones and worth specific
attention.

## Intercepting Traffic

```bash
# mitmproxy speaks HTTP/2 and can decode gRPC with a schema
mitmproxy --mode regular --set http2=true
#   the gRPC content-view renders protobuf; supply .proto for field names

# Burp: enable HTTP/2, and use a protobuf decoder extension
#   without one, you see length-prefixed binary frames

# gRPC-Web is easier — it rides HTTP/1.1 with base64 or binary framing,
# so a normal proxy sees the requests
```

**gRPC framing**: each message is a 1-byte compression flag, a 4-byte
big-endian length, then the protobuf bytes. When a decoder shows nothing,
strip those five bytes before feeding the payload to `protoc --decode_raw`.

```bash
python3 -c "
import sys
d = sys.stdin.buffer.read()
sys.stdout.buffer.write(d[5:])" < frame.bin | protoc --decode_raw
```

Clients that ignore the system proxy need a network-layer redirect; see
`bypassing-mobile-pinning`.

## What to Test

The bug classes are the same as any API, but gRPC changes where they hide.

**Authorization per method.** gRPC has no path-based access control, so a
reverse proxy or WAF that filters `/admin/*` does nothing. Each method must
check authorization itself — enumerate every method from reflection and call
each one with a low-privilege token.

```bash
for m in $(grpcurl -plaintext target:50051 list package.Service | tail -n +2); do
  echo "== $m"; grpcurl -H "authorization: Bearer $LOW_PRIV" -plaintext -d '{}' target:50051 "$m" 2>&1 | head -3
done
```

**Internal services exposed.** gRPC is a service-mesh protocol, so many
services were written assuming only other services would call them. If you can
reach one directly, expect no authentication at all — and expect it to trust
identity claims passed as ordinary request fields or metadata.

**Metadata trust.** Look for headers the service reads as identity:
`x-user-id`, `x-tenant-id`, `x-forwarded-user`. If a gateway sets them and the
service trusts them, sending them yourself is a complete authentication bypass.

```bash
grpcurl -H 'x-user-id: 1' -H 'x-role: admin' -plaintext -d '{}' target:50051 package.Service/GetProfile
```

**Unknown-field injection.** Protobuf ignores fields it does not recognize,
but intermediate services may forward them. More usefully: add fields the
*client* never sends but the *server* schema defines — `is_admin`,
`internal_notes`, `tenant_id` — the mass-assignment equivalent.

**Type confusion and resource exhaustion.** Wire types are loosely enforced;
send a `bytes` where a `string` is expected, deeply nested messages to blow
the recursion limit, or a huge `repeated` field. Check for a configured
message size limit.

**TLS and mTLS posture.** Many gRPC deployments use `insecure` channels
internally. Check whether the service accepts plaintext, and whether mTLS is
required or merely optional.

## Rationalizations to Reject

- *"Burp shows nothing, the app isn't making requests."* Burp needs HTTP/2
  enabled, and gRPC clients often bypass the system proxy entirely.
- *"I don't have the .proto, so I can't test it."* `protoc --decode_raw`
  recovers structure from any message. Field numbers are all you need.
- *"Reflection is disabled, so the methods are hidden."* The client knows the
  schema. Extract the descriptors from the client binary.
- *"The gateway enforces authorization."* The gateway sees method names, not
  intent, and anything that reaches the service directly bypasses it entirely.
- *"It's internal-only."* Confirm that. Service meshes leak, and "internal"
  usually means "no authentication".
- *"The client never sends that field."* You are not the client.

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Initial Access** (TA0001)

- [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application — see also `testing-web-applications`, `testing-apis`, `enumerating-network-services`, `attacking-graphql`, `exploiting-deserialization`, `exploiting-ssrf`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- `testing-apis` — the general API methodology this specializes
- `auditing-code-for-vulnerabilities` — reading `.proto` and handlers in source
- `bypassing-mobile-pinning` — when a mobile gRPC client ignores your proxy
- `exploiting-cloud-platforms` — service mesh and internal exposure context
- grpcurl, grpcui, protoc, protobuf-inspector, protod, mitmproxy
