---
name: producing-threat-intelligence
description: Produce cyber threat intelligence by pivoting on indicators to find related infrastructure, tracking actors and campaigns, enriching and contextualizing IOCs, applying attribution discipline and analytic confidence, and packaging finished intel products tied to a consumer's decision. Covers the intelligence lifecycle, the Diamond Model and Pyramid of Pain, STIX/MISP/OpenCTI storage, TLP sharing, and passive enrichment via passive DNS, crt.sh, Shodan, Censys, GreyNoise, and VirusTotal. Use when pivoting from a domain, IP, hash, or certificate to related infrastructure, tracking a threat actor or campaign, enriching raw indicators, writing a finished intel report, assessing an external report's relevance to your org, or building a threat model of adversaries that matter to you.
---

# Producing Threat Intelligence

Intelligence is not a pile of indicators — it is analysis that reduces a
decision-maker's uncertainty. An IOC with no context, no confidence, and no
recommended action is data, not intelligence. Attribution is a claim you must
be able to defend from evidence, not a guess dressed in a threat-actor name.
The test of a finished product is simple: did someone decide something
differently because of it?

## When to Use

- Pivoting from a domain, IP, hash, TLS certificate, or registrant to related
  infrastructure
- Tracking a threat actor or campaign over time
- Enriching and contextualizing raw indicators into usable intelligence
- Producing a finished intelligence product for a defined consumer
- Assessing whether an external vendor or government report is relevant to
  your organization
- Building and curating a threat model of the adversaries that actually
  matter to you

## When NOT to Use

- **Searching your OWN telemetry for the activity** — use `hunting-threats`
- **Reversing a specific sample** — use `analyzing-malware`
- **Resolving an ATT&CK technique ID to a skill** — use
  `mapping-attack-techniques`
- **An active, confirmed incident** — use `responding-to-incidents`
- **Turning intel into deployed detection rules** — use
  `engineering-detections`

## The Intelligence Lifecycle

Every product moves through the same loop. Naming the stages is not
bureaucracy — it is where you catch the two failures that make CTI worthless.

```
1. Direction     — whose decision, which question (a PIR)
2. Collection    — gather against the requirement, not everything reachable
3. Processing     — normalize, deduplicate, translate, enrich
4. Analysis      — assess, weigh hypotheses, assign confidence
5. Dissemination — deliver in a form the consumer can act on
6. Feedback      — did it help; refine the next requirement
```

The two failures that account for most wasted CTI effort are at the ends of
the loop, not the middle:

- **Skipping direction** produces intelligence nobody asked for. Without a
  Priority Intelligence Requirement (PIR) naming the consumer and the decision,
  you collect what is easy and report what is interesting, and it lands on no
  one's desk. Start from the question, not the feed.
- **Skipping dissemination** produces analysis that never reaches a decision.
  A brilliant assessment sitting in a wiki nobody reads changed nothing. The
  product is not done when it is written; it is done when it is in front of
  the person who acts on it, in the form and at the time they need it.

Write the PIR before collecting. Examples: "Which ransomware crews target our
sector and what is their initial-access tradecraft?" "Is the actor in last
week's incident likely to return?" "Does this vendor report describe a threat
to us?" Each names a consumer and a decision.

## Indicator Pivoting

Pivoting expands one observable into an infrastructure picture. The discipline
is to stay **passive first** — every pivot below reads third-party data or
historical records, none of it touches the adversary's live infrastructure.

| Start from | Pivot via | Finds |
| --- | --- | --- |
| Domain / IP | Passive DNS (PDNS) | Historical resolutions, sibling domains on an IP, IPs a domain used |
| Domain | WHOIS / registration history | Registrant email, registrar, creation date, name-server reuse |
| Domain / IP | Certificate transparency (crt.sh) | Other hostnames on the same cert, SAN reuse, issuance timeline |
| IP / service | TLS fingerprints — JARM (server), JA3/JA3S (client/server handshake) | Hosts running the same C2 or framework default TLS stack |
| Web service | Favicon hash (Shodan `http.favicon.hash`, Censys) | Other servers serving the identical panel or login page |
| IP / host | Shodan / Censys banners | Open ports, product versions, response bodies, self-signed cert CNs |

A worked pivot chain: a phishing domain resolves (PDNS) to an IP; crt.sh shows
the cert's SANs cover four more lookalike domains; the IP's JARM matches a
known Cobalt Strike default; Shodan's favicon hash for the panel returns nine
more IPs serving the same interface. One indicator became a cluster of ten,
none of which required contacting the adversary.

```
# Certificate transparency — all certs/SANs seen for a domain
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Shodan: everything serving an identical favicon
shodan search "http.favicon.hash:-247388890"

# Censys: hosts presenting a given JARM fingerprint
censys search "services.jarm.fingerprint: <jarm_hash>"
```

**Do not tip off the adversary.** Do not curl the live C2, resolve its domain
from a network attributable to you, submit the still-active sample to a public
multi-scanner, or scan the infrastructure directly — each of those tells the
operator you are watching and invites rotation or a burn of your visibility.
Prefer passive datasets. If active interaction is genuinely required, route it
through infrastructure that is not attributable to you and make it a
deliberate, logged decision.

## Frameworks for Prioritizing What to Track

### Diamond Model

Every intrusion event has four connected features: **adversary**, **capability**
(malware, tooling, exploits), **infrastructure** (C2, staging, redirectors),
and **victim**. Any feature leads to another — a capability points to the
adversary who wields it; infrastructure points to other victims. Pivoting is
literally traversing the edges of the diamond. Record findings against these
four vertices so a partial picture composes with the next one.

### Pyramid of Pain

Not all indicators cost the adversary the same to change. The higher you track,
the more it hurts them and the longer your intelligence survives.

```
TTPs             ← hardest to change — track these
Tools
Network/Host artifacts
Domain names
IP addresses
Hash values      ← trivial to change — useful now, dead tomorrow
```

Hashes and IPs are cheap for the adversary to rotate, so intelligence built on
them decays in days. Tooling and TTPs force real redevelopment. Prioritize
collection and tracking toward the top of the pyramid; treat the bottom as
perishable and time-stamp it accordingly.

## Attribution Discipline

Attribution is the most abused word in CTI. Keep two operations strictly
separate:

- **Clustering** groups activity by shared observables (infrastructure
  patterns, tooling, TTPs, tradecraft, timing). It is defensible from evidence
  and it is what you should do most of the time.
- **Naming** asserts that a cluster IS a known actor. It inherits that actor's
  history, motivation, and geopolitical baggage — and it is frequently wrong.

Use temporary, non-committal labels for clusters you have not confirmed:
UNC-style uncategorized designators, or your own internal `CLUSTER-####`. Only
promote a cluster to a named actor when the evidence supports it, and state
what evidence. "Same TTPs" is weak grounds: shared tooling, shared exploit
kits, and public tradecraft mean two operators can look identical.

**Analytic confidence** is a separate axis from the claim. State it explicitly:

- **High** — consistent, corroborated evidence from multiple independent
  sources; few plausible alternatives.
- **Moderate** — credible evidence, but gaps or single-source dependence
  leave room for alternatives.
- **Low** — fragmentary or uncorroborated; the assessment is a working
  hypothesis.

Confidence is not the same as how strongly you feel it. It is a function of
the evidence and the number of surviving alternative explanations.

**Analysis of Competing Hypotheses (ACH):** when attribution or intent is
contested, enumerate the plausible hypotheses first, then list the evidence,
and score each item by how well it is *consistent* with each hypothesis. The
goal is to find evidence that *disconfirms* — the hypothesis left standing
after you try to break it is stronger than the one you set out to prove.

**Cognitive-bias traps** to name and resist:

- **Mirror-imaging** — assuming the adversary reasons, prioritizes, and
  operates the way you would.
- **Confirmation bias** — collecting and weighting evidence that supports the
  answer you already reached, discounting what contradicts it.
- **Anchoring** — locking onto the first attribution offered (often a vendor's)
  and adjusting insufficiently as new evidence arrives.

## Structured Storage and Standards

Free-text notes do not compose, correlate, or feed automation. Store
intelligence in a structured model from the start.

- **STIX 2.1** — the interchange grammar. Objects (SDOs) include
  `indicator`, `malware`, `threat-actor`, `campaign`, `intrusion-set`,
  `infrastructure`, `identity`, and `attack-pattern`; relationships (SROs)
  like `uses`, `targets`, `indicates`, `attributed-to` connect them. A STIX
  `indicator` carries a pattern, valid-from/until, and confidence — context
  the bare IOC lacks.
- **MISP** — event-centric sharing platform. **Events** hold **attributes**
  (the indicators) with types, categories, and per-attribute IDS flags;
  **galaxies** attach actor, tooling, and ATT&CK context; correlation across
  events surfaces overlap between your data and partners'.
- **OpenCTI** — a knowledge graph that ingests STIX, links objects across
  reports, and lets you query relationships (which campaigns use this malware,
  which infrastructure this actor reuses) rather than re-deriving them.
- **TLP** — the sharing classifier. Tag every product: **TLP:RED** (named
  recipients only), **TLP:AMBER** / **TLP:AMBER+STRICT** (their org, or their
  org only), **TLP:GREEN** (community), **TLP:CLEAR** (no restriction). The
  tag travels with the data; downgrading it is the sharer's call, never the
  recipient's.

## Enrichment Sources

Enrichment converts a bare observable into something with context and
confidence. Match the source to the question.

| Source | Answers |
| --- | --- |
| VirusTotal | Detections, relationships (contacted domains, dropped files, siblings), first/last seen, community context |
| Passive DNS (Farsight/DNSDB, SecurityTrails, Circl) | Resolution history, co-hosted domains, infrastructure reuse over time |
| Shodan / Censys | Exposed services, banners, certs, JARM, favicon hashes — the internet-facing view without touching the target directly |
| GreyNoise | Whether an IP is mass-scanning the whole internet (background noise) versus activity aimed at you |
| URLScan | What a URL actually serves — page content, redirects, resources, screenshot — without you browsing it |

**GreyNoise earns its place by subtraction.** Most flagged IPs are internet
background radiation — opportunistic scanners hitting everyone. GreyNoise tells
you whether an indicator is that noise or something targeted, so you stop
burning analyst hours enriching a Shodan crawler and focus on what is aimed at
your organization.

## Producing the Finished Product

The report is the product; everything upstream is inventory. Structure it for
a decision-maker, not for an analyst admiring the work.

- **BLUF (bottom line up front)** — the assessment and its "so what" in the
  first two sentences. If the reader stops after the first paragraph, they
  should still have the answer.
- **Confidence and sourcing** — state analytic confidence on each key
  judgment, and separate what you observed from what you assess. Attribute
  claims to their evidence; distinguish single-source from corroborated.
- **So what / recommended action** — tie the analysis to the consumer's
  decision. What should they do, block, hunt for, or prioritize, and why now?
  An assessment with no recommended action leaves the reader to reinvent the
  implication, and most will not.

Write to the audience: an executive needs the risk and the decision; a SOC
lead needs the detections and the pivots. The same underlying intelligence
becomes two different products.

## CTI in the Defensive Loop

Threat intelligence is not a terminal deliverable — it is the fuel for the
rest of the defensive program, and it consumes their output in return.

- It **feeds detection**: TTPs and tooling become deployed rules via
  `engineering-detections`. Hand over behaviors and tiered indicators, not a
  raw feed.
- It **feeds hunting**: an intel report's described behavior (not its dead
  IOCs) becomes a hypothesis in `hunting-threats` run against your telemetry.
- It **consumes ATT&CK mappings**: resolve techniques through
  `mapping-attack-techniques` so your products speak the same taxonomy as
  detection and hunting, and coverage gaps become visible.

Intelligence that does not flow into detection, hunting, or a decision is a
research hobby, not a capability.

## Rationalizations to Reject

- *"More indicators is better intelligence."* No. Unprioritized IOCs are
  noise that buries the few that matter. Volume is not value; a ranked handful
  with context beats a feed of ten thousand.
- *"It's the same actor — the TTPs match."* TTP overlap is shared tooling as
  often as shared operator. Public kits and leaked frameworks make unrelated
  crews look identical. Cluster on the evidence; do not name.
- *"The vendor report attributes it, so it's confirmed."* A vendor's
  attribution is one source with its own biases and incentives. Read their
  evidence, weigh it, and assign your own confidence — do not inherit theirs.
- *"We should scan the C2 to learn more."* You just told the operator you are
  watching, and they rotate. Passive datasets first; active interaction only
  from non-attributable infrastructure as a deliberate decision.
- *"High confidence — it feels right."* Confidence must be defensible from
  evidence and the count of surviving alternatives, not from conviction.
  If you cannot show the evidence, it is not high confidence.
- *"We produced the report, the job's done."* Undisseminated intelligence
  changed no decision. The lifecycle does not end at analysis; it ends when
  the consumer has acted — or told you why they did not.
- *"This report is about someone else's sector, so it's irrelevant."* Relevance
  is a judgment you make against your own threat model, not an assumption.
  The TTPs may transfer even when the target does not.

## References

- `hunting-threats` — running intel-derived hypotheses against your own
  telemetry
- `analyzing-malware` — sample-derived config, capability, and IOCs that feed
  intel
- `engineering-detections` — converting tracked TTPs into deployed rules
- `mapping-attack-techniques` — resolving and standardizing ATT&CK references
- `responding-to-incidents` — the consumer and source during an active event
- `reporting-security-findings` — structure and language for the finished
  written product
- MISP, OpenCTI — structured storage, correlation, and sharing platforms
- STIX 2.1 — the object and relationship model for interchange
- crt.sh — certificate transparency search for infrastructure pivoting
- Shodan, Censys — internet-wide service, banner, JARM, and favicon search
- GreyNoise — separating internet background noise from targeted activity
- VirusTotal — detection, relationship, and enrichment context
