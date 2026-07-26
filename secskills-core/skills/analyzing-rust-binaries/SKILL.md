---
name: analyzing-rust-binaries
description: Reverse engineer Rust binaries — demangling legacy and v0 symbol schemes, recognizing monomorphized generics, Result and Option control flow, trait object vtable dispatch, and panic-site strings that leak source paths and crate names. Use when a binary contains rustc version strings, core::panicking, or _ZN/_R mangled symbols, when a stripped binary is unexpectedly large, or when analyzing Rust malware or a Rust service.
---

# Analyzing Rust Binaries

Rust binaries are large, statically linked, and full of inlined generic code —
but they leak more than most people expect. Panic sites embed the source file
path and line, symbols carry crate and module structure, and the standard
library's formatting machinery is instantly recognizable. The job is knowing
which parts are yours and which are the 90% that is `core`, `alloc`, and
vendored crates.

## When to Use

- `strings` shows `rustc version`, `core::panicking`, `/rustc/<hash>/library/`
- Symbols begin with `_ZN...17h<hex>E` (legacy) or `_R` (v0 mangling)
- A stripped binary is 3–30 MB with minimal dynamic imports
- Analyzing Rust malware, a Rust CLI, or a compiled Rust service

## When NOT to Use

- **Go binaries** — use `analyzing-go-binaries`; symbol recovery differs entirely
- **.NET or Unity** — use the matching skill
- **Suspected malware, before containment** — use `analyzing-malware` first
- **Source is available** — use `auditing-code-for-vulnerabilities`, which has
  the Rust `unsafe` checklist

## Confirm and Fingerprint

```bash
strings -n 8 target | rg -m8 'rustc version|/rustc/[0-9a-f]{40}|core::panicking|cargo/registry'
```

Two artifacts do most of the work before you disassemble anything:

**Panic strings leak the source tree.** Rust embeds the file path and line
number of every `panic!`, `unwrap()`, and bounds check. That gives you the
crate layout, the developer's directory structure, and often the project name.

```bash
strings -n 10 target | rg 'src/[a-z_/]+\.rs' | sort -u | head -40
# → src/main.rs, src/crypto/aes.rs, /home/dev/projects/implant/src/c2.rs
```

**Registry paths name the dependencies.** Vendored crates compiled in leave
their `~/.cargo/registry/src/.../<crate>-<version>/` paths in panic sites,
which is effectively a dependency list.

```bash
strings target | rg -o 'cargo/registry/src/[^/]+/([a-z0-9_-]+-[0-9.]+)' -r '$1' | sort -u
```

That combination — module layout plus dependency list — usually tells you what
the binary does before a single instruction is read.

## Demangle

Rust has two mangling schemes, and tools must handle both.

```bash
# Legacy: _ZN4core3fmt5Write9write_fmt17h<16 hex>E
nm -C target | head -30
rustfilt < symbols.txt

# v0 (RFC 2603): starts with _R, encodes generics and paths properly
rustfilt      # handles both
# Ghidra 11+ and IDA 8+ have v0 demanglers; enable Rust demangling in the
# analyzer options rather than reading raw symbols
```

```bash
# Filter to your target's code. Everything under core::, alloc::, std::, and
# a registry crate name is stock.
nm -C target 2>/dev/null | rg -v '^.* (core|alloc|std|hashbrown|serde|tokio)::' | head -40
```

When symbols are fully stripped, fall back to the panic strings: each one is
adjacent to the function that contains it, so cross-referencing a panic
message with a known source path names the surrounding function.

## Reading Rust in a Disassembler

Five patterns account for most of the confusion:

**Monomorphization.** A generic function is compiled once per concrete type,
so `Vec<u8>::push` and `Vec<String>::push` are separate functions with similar
bodies. Expect duplicates, and do not assume two near-identical functions are
copy-paste.

**`Result` and `Option` returns.** These are enums returned by value, often in
two registers — a discriminant and a payload. A function returning
`Result<T, E>` looks like it returns a struct; the branch immediately after
the call testing the first register is the error check. Recognizing this makes
error paths readable, and error paths are where the bugs are.

**Bounds checks everywhere.** Every slice index emits a comparison and a
conditional branch to a panic site. These clutter the listing; learn to skip
them. Their *absence* is informative — it means `unsafe` or `get_unchecked`.

**Trait object dispatch.** `dyn Trait` calls go through a vtable: a pointer
pair (data, vtable), then an indirect call at a fixed vtable offset. Recover
the vtable to recover the concrete type, the same way you would for C++.

**String handling.** Rust `String` and `&str` are pointer+length with no
terminator, exactly like Go. Adjacent literals run together in `strings`
output; find the length constant next to the pointer load.

## Finding the Interesting Code

```bash
# Panic paths point at your code; use them as anchors
strings -t x target | rg 'src/' | head -30      # offsets included
# Cross-reference an offset in the disassembler to land in the owning function

# Crypto and network crates are recognizable by their panic paths
strings target | rg -i 'ring-|rustls|openssl|aes-gcm|chacha20|reqwest|hyper|tokio'
```

For a service or implant, the fastest route is: identify the async runtime
(`tokio` is near-universal), find the request handler or the C2 loop by its
panic paths, then read outward.

## Rust-Specific Security Review

If you are hunting bugs rather than behaviour:

- **`unsafe` blocks** are where memory-safety bugs live. In a binary, look for
  the absence of bounds checks around indexing, and for `from_raw_parts` /
  `transmute` call sites if symbols survive.
- **Integer overflow** is checked in debug builds and wraps silently in
  release. A release binary's arithmetic has no overflow traps.
- **`unwrap()` / `expect()` on attacker-controlled input** is a remote panic —
  a denial of service, and a real finding for a network service.
- **FFI boundaries.** `extern "C"` functions taking pointers are where Rust's
  guarantees stop.
- **Deserialization** with `serde` into types whose invariants the constructor
  enforces but `Deserialize` does not.

With source, use `auditing-code-for-vulnerabilities` and `cargo geiger`.

## Rust Malware Notes

Rust is increasingly used for ransomware and loaders, largely for
cross-compilation and analyst friction. What still helps you:

- **Panic paths leak the developer's build environment** — usernames, project
  names, and directory structures, which are attribution-relevant.
- **The dependency list from registry paths** identifies the networking and
  crypto crates, which narrows the C2 protocol and the encryption scheme
  before you read the code.
- **`rustc` version** in the binary dates the build.
- Samples that strip aggressively still emit bounds-check panic sites unless
  compiled with `panic=abort` and heavy `strip`; when even those are gone,
  note it as a deliberate anti-analysis measure.

Hand containment and IOC work to `analyzing-malware`.

## Rationalizations to Reject

- *"It's stripped, nothing to recover."* Panic strings survive stripping and
  name the source files.
- *"Thousands of functions."* Most are `core`/`alloc`/vendored crates. Filter
  by demangled path.
- *"These two functions are identical, it's copy-paste."* It is
  monomorphization of one generic.
- *"The decompiler shows a struct return I don't understand."* It is
  `Result`/`Option`. The discriminant test after the call is the error branch.
- *"Rust is memory-safe, so there are no memory bugs."* `unsafe` and FFI exist,
  and logic bugs are unaffected by the borrow checker.
- *"The strings are corrupted."* Rust strings are pointer+length, not
  null-terminated.

## References

- `analyzing-binaries` — general triage, dynamic analysis, anti-analysis
- `analyzing-go-binaries` — the other statically-linked-and-large case
- `analyzing-malware` — containment and IOCs for Rust samples
- `auditing-code-for-vulnerabilities` — the Rust `unsafe` checklist with source
- rustfilt, Ghidra/IDA Rust demanglers, `cargo-geiger`, Binary Ninja
