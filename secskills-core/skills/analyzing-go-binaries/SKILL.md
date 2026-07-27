---
name: analyzing-go-binaries
description: Reverse engineer Go binaries by recovering function names and types from pclntab and moduledata using GoReSym, redress, and IDA/Ghidra Go plugins, and by reading Go's non-standard calling convention, interface dispatch, and string layout. Use when a binary contains Go runtime strings, when strings show runtime.main or go:buildid, when a stripped binary is unexpectedly large, or when analyzing Go malware or a Go-based service.
verified: 2026-07-27
---

# Analyzing Go Binaries

Go binaries look hostile — statically linked, tens of megabytes, no imports
you recognize, and "stripped" in a way that makes tools show thousands of
`sub_` functions. They are not. Go ships its own symbol table for runtime
reflection and panic traces, and `strip` does not remove it. Recover it and
the binary becomes one of the easiest targets there is.

## When to Use

- `strings` shows `runtime.main`, `go:buildid`, `go.buildinfo`, or
  `runtime.gopanic`
- A "stripped" binary is 5–50 MB with almost no dynamic imports
- The disassembler shows thousands of unnamed functions and unreadable strings
- Analyzing Go malware, a Go CLI tool, or a compiled Go service

## When NOT to Use

- **Rust binaries** — use `analyzing-rust-binaries`; the symbol recovery is
  entirely different
- **.NET assemblies** — use `analyzing-dotnet-assemblies`
- **Suspected malware, before containment** — use `analyzing-malware` for the
  environment, then come back here
- **General native RE** — use `analyzing-binaries`

## Confirm It Is Go, and Which Version

```bash
strings -n 6 target | rg -m5 'go1\.[0-9]+|go:buildid|runtime\.main|GOROOT'
go version target                     # works on unstripped and many stripped builds
go version -m target                  # module list and build settings — free SBOM
```

`go version -m` is the highest-value first command. It prints the module
dependency graph with versions, which gives you the third-party libraries in
use before you disassemble anything — often answering the question outright
(which HTTP library, which crypto, which C2 framework).

The Go version matters because `pclntab` layout changed at 1.2, 1.16, 1.18,
and 1.20. Tooling that fails is usually version mismatch, not a hardened
binary.

## Recover Symbols

```bash
# GoReSym — extracts pclntab, moduledata, types, and build info
GoReSym -t -d -p target > syms.json
#   -t  user type metadata
#   -d  include standard library
#   -p  paths

# redress — Go-aware analysis, works well when GoReSym struggles
redress info target
redress symbols target
redress types target

# Load into the disassembler
#   IDA:    AlphaGolang, golang_loader_assist, or the GoReSym IDA script
#   Ghidra: GolangAnalyzerExtension, or gotools
#   Binja:  the Golang loader plugin
```

After applying symbols, functions carry their real names —
`main.processRequest`, `crypto/tls.(*Conn).Handshake`,
`github.com/vendor/pkg.Function`. **Filter to `main.*` and to third-party
module paths.** Everything under `runtime.`, `internal/`, and the standard
library is stock and is 90%+ of the function count.

```bash
jq -r '.UserFunctions[].FunctionName' syms.json | rg -v '^(runtime|internal|reflect|sync)\.' | head -40
```

## Reading Go Code in a Disassembler

Four things make Go listings confusing until you know them:

**Strings have no terminator.** Go strings are a pointer plus a length, so
`strings` output runs adjacent literals together and the disassembler shows a
pointer load followed by a length constant. Look for the pair — the constant
next to the pointer is the length, and that is how you slice the correct
substring out of the blob.

**Calling convention.** Before Go 1.17 all arguments and return values went on
the stack, not in registers. From 1.17 a register ABI applies on amd64/arm64.
A decompiler configured for the C convention will show wrong arguments;
Go-aware plugins fix this, and it is the main reason decompiler output looks
nonsensical.

**Interface dispatch.** Calls through an interface go via an `itab` — a table
holding the concrete type and its method pointers. To resolve a call target,
find the `itab` being loaded, then read the concrete type. Type recovery tools
name these, which turns an indirect call into a readable one.

**Goroutines and defers.** `go f()` compiles to `runtime.newproc` with `f` as
an argument, so concurrent logic does not appear as a direct call. `defer`
becomes `runtime.deferproc`/`deferreturn`, which scatters cleanup code away
from where it was written. When following control flow, check `newproc` call
sites for work you would otherwise miss entirely.

## Type Recovery

Go embeds full type descriptors for reflection. That means struct field names
and layouts are recoverable — including the JSON tags that map straight to a
wire protocol.

```bash
redress types target | rg -A10 'type main\.'
# Struct tags like `json:"api_key"` recover the exact protocol field names
```

This is the fastest route to a Go service's API surface or a Go implant's C2
message format: recover the request and response structs, and you have the
protocol without reading a single instruction.

## Go-Specific Security Review

If the job is finding bugs rather than understanding behaviour, the Go-specific
classes worth targeting:

- **Ignored errors.** `_ =` on a function returning an error, especially
  around auth, crypto, and file operations.
- **`math/rand` for security values.** Token, session ID, or nonce generation
  using the non-crypto RNG.
- **`InsecureSkipVerify: true`** in a `tls.Config`.
- **`fmt.Sprintf` building SQL, shell commands, or URLs.**
- **Data races** on shared maps and structs — often the source of
  authorization bugs under load.
- **`os/exec` with a shell**, or with an argument built from input.

With source available, use `auditing-code-for-vulnerabilities` and
`govulncheck`; the above is for when you only have the binary.

## Go Malware Notes

Go is common in cross-platform implants, and it leaves useful artifacts:

- **Module list from `go version -m`** identifies the frameworks used —
  networking libraries, crypto, and sometimes the C2 project itself.
- **Build paths** in the symbol table leak developer usernames, project names,
  and directory structures.
- **`main.` package function names** frequently survive because stripping does
  not remove `pclntab`, giving you a capability list for free.
- Some samples strip `pclntab` deliberately or use tools that mangle
  `moduledata`. When GoReSym and redress both fail on a sample that is
  otherwise clearly Go, treat that as an evasion indicator worth reporting —
  and fall back to scanning for the type descriptors directly.

Hand IOC and detection output to `analyzing-malware` and
`engineering-detections`.

## Rationalizations to Reject

- *"It's stripped, so there are no symbols."* `strip` does not remove
  `pclntab`. Run GoReSym before concluding anything.
- *"The decompiler output is garbage."* It is using the wrong calling
  convention. Apply a Go-aware plugin.
- *"Thousands of functions, this will take weeks."* Almost all are runtime and
  stdlib. Filter to `main.*` and vendored modules.
- *"The strings are all mashed together."* Go strings are pointer+length.
  Slice by the length constant.
- *"The tool failed, this binary is protected."* Check the Go version against
  the tool's supported `pclntab` versions first.
- *"I need to trace every goroutine."* Find `runtime.newproc` call sites and
  read the function passed to them.

## References

- `analyzing-binaries` — general triage and dynamic analysis around this
- `analyzing-malware` — containment and IOC extraction for Go samples
- `auditing-code-for-vulnerabilities` — the Go bug-class checklist when source exists
- GoReSym, redress, AlphaGolang, GolangAnalyzerExtension, `go version -m`
