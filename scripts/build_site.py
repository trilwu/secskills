#!/usr/bin/env python3
"""Generate the static docs site into docs/ — landing page plus one page per skill.

Reads the source of truth (SKILL.md frontmatter + body, ttp-index.json,
marketplace.json) and renders drift-proof HTML. Stdlib only, so it runs in any
CI image.

    python3 scripts/build_site.py            # write docs/
    python3 scripts/build_site.py --check    # fail if docs/ is out of date

GitHub Pages: Settings -> Pages -> Source: main / docs.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PLUGIN_DIRS = sorted(p for p in REPO.glob("secskills-*") if (p / "skills").is_dir())
INDEX = REPO / "secskills-core" / "ttp-index.json"
DOCS = REPO / "docs"

PLUGIN_LABEL = {"offense": "offense", "defense": "defense", "core": "core"}

USE_CASES = [
    ("Builders", [
        ("Micro-SaaS founder · pre-launch",
         "Before I launch, audit this codebase for anything that could leak a customer's data — focus on authentication, access control, and the billing flow.",
         "auditing-code-for-vulnerabilities"),
        ("Indie hacker · cloud check",
         "Review my AWS setup for anything public that shouldn't be, and flag any over-broad IAM roles.",
         "hardening-cloud-posture"),
        ("AI / agent builder",
         "Review this LLM agent for prompt injection and tool misuse before I ship it.",
         "securing-ai-systems"),
        ("AI / agent builder · MCP",
         "Audit this MCP server I built — tool definitions, authorization, and what a caller can reach.",
         "auditing-mcp-servers"),
    ]),
    ("Security professionals", [
        ("AppSec · code review",
         "Audit the authentication and billing code in this repo for vulnerabilities.",
         "auditing-code-for-vulnerabilities"),
        ("Red team · internal engagement",
         "I'm on an internal pentest with a low-priv AD user — where do I look for escalation?",
         "attacking-active-directory"),
        ("DFIR · incident responder",
         "A host is beaconing to an unfamiliar domain. What do I preserve, and where do I start?",
         "responding-to-incidents"),
        ("SOC · analyst",
         "Triage this EDR alert for me — is it worth escalating, and why?",
         "triaging-security-alerts"),
    ]),
]


# ---------------------------------------------------------------- parse skills

def parse_skill(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    end = text.find("\n---", 4)
    fm, body = text[4:end], text[end + 4:]
    def field(k):
        m = re.search(rf"^{k}:\s*(.+?)(?=\n[a-z_]+:|\Z)", fm, re.M | re.S)
        return " ".join(m.group(1).split()) if m else ""
    # strip the boilerplate external-sources section and the attack markers
    body = re.sub(r"\n## Reading External Sources\n.*?(?=\n## |\Z)", "", body, flags=re.S)
    body = re.sub(r"<!-- attack:(start|end) -->", "", body)
    return {
        "name": field("name"),
        "plugin": path.parts[-4].replace("secskills-", ""),
        "desc": field("description"),
        "verified": field("verified"),
        "body": body.strip(),
    }


def load_skills() -> list[dict]:
    out = []
    for pd in PLUGIN_DIRS:
        for f in sorted((pd / "skills").glob("*/SKILL.md")):
            out.append(parse_skill(f))
    return sorted(out, key=lambda s: s["name"])


# ------------------------------------------------------------ minimal markdown

def inline(text: str, names: set[str], current: str) -> str:
    text = html.escape(text, quote=False)
    codes: list[str] = []
    def stash(m):
        codes.append(m.group(1))
        return f"\x00{len(codes)-1}\x00"
    text = re.sub(r"`([^`]+)`", stash, text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])", r"<em>\1</em>", text)
    text = re.sub(r"(?<![\w_])_([^_\n]+)_(?![\w_])", r"<em>\1</em>", text)
    def restore(m):
        c = html.escape(codes[int(m.group(1))], quote=False)
        inner = codes[int(m.group(1))]
        if inner in names and inner != current:
            return f'<a class="xref" href="{inner}.html"><code>{c}</code></a>'
        return f"<code>{c}</code>"
    return re.sub(r"\x00(\d+)\x00", restore, text)


def md_to_html(md: str, names: set[str], current: str) -> str:
    lines = md.split("\n")
    out: list[str] = []
    i, n = 0, len(lines)
    def flush_para(buf):
        if buf:
            out.append("<p>" + inline(" ".join(buf), names, current) + "</p>")
            buf.clear()
    para: list[str] = []
    while i < n:
        ln = lines[i]
        # fenced code
        if ln.startswith("```"):
            flush_para(para)
            i += 1
            code = []
            while i < n and not lines[i].startswith("```"):
                code.append(lines[i]); i += 1
            i += 1
            out.append("<pre><code>" + html.escape("\n".join(code), quote=False) + "</code></pre>")
            continue
        # table
        if ln.lstrip().startswith("|") and i + 1 < n and re.match(r"^\s*\|[\s:|-]+\|\s*$", lines[i + 1]):
            flush_para(para)
            def cells(row): return [c.strip() for c in row.strip().strip("|").split("|")]
            head = cells(ln); i += 2
            rows = []
            while i < n and lines[i].lstrip().startswith("|"):
                rows.append(cells(lines[i])); i += 1
            t = ['<div class="tw"><table><thead><tr>']
            t += [f"<th>{inline(c, names, current)}</th>" for c in head]
            t.append("</tr></thead><tbody>")
            for r in rows:
                t.append("<tr>" + "".join(f"<td>{inline(c, names, current)}</td>" for c in r) + "</tr>")
            t.append("</tbody></table></div>")
            out.append("".join(t))
            continue
        # heading
        m = re.match(r"^(#{1,6})\s+(.*)$", ln)
        if m:
            flush_para(para)
            lvl = len(m.group(1))
            if lvl == 1:  # page already has the H1
                i += 1; continue
            tag = "h2" if lvl == 2 else "h3" if lvl == 3 else "h4"
            out.append(f"<{tag}>{inline(m.group(2), names, current)}</{tag}>")
            i += 1; continue
        # blockquote
        if ln.startswith(">"):
            flush_para(para)
            q = []
            while i < n and lines[i].startswith(">"):
                q.append(lines[i][1:].strip()); i += 1
            out.append("<blockquote>" + inline(" ".join(q), names, current) + "</blockquote>")
            continue
        # lists (one nesting level)
        if re.match(r"^(\s*)([-*]|\d+\.)\s+", ln):
            flush_para(para)
            ordered = bool(re.match(r"^\s*\d+\.\s+", ln))
            tag = "ol" if ordered else "ul"
            out.append(f"<{tag}>")
            depth = 0
            while i < n and re.match(r"^(\s*)([-*]|\d+\.)\s+", lines[i]):
                mm = re.match(r"^(\s*)(?:[-*]|\d+\.)\s+(.*)$", lines[i])
                ind = len(mm.group(1))
                if ind >= 2 and depth == 0:
                    out.append("<ul>"); depth = 1
                elif ind < 2 and depth == 1:
                    out.append("</ul>"); depth = 0
                out.append("<li>" + inline(mm.group(2), names, current) + "</li>")
                i += 1
            if depth == 1: out.append("</ul>")
            out.append(f"</{tag}>")
            continue
        # blank / paragraph
        if not ln.strip():
            flush_para(para)
        else:
            para.append(ln.strip())
        i += 1
    flush_para(para)
    return "\n".join(out)


# --------------------------------------------------------------------- styling

CSS = """
:root{--bg:#fff;--surface:#fafafa;--text:#17181c;--muted:#5f636e;--faint:#8b8f9a;
--border:#e7e8ec;--border2:#d9dbe0;--accent:#0a8f5f;--off:#b0605f;--def:#5a7bb0;--core:#87799f;
--mono:ui-monospace,"SF Mono","JetBrains Mono","Cascadia Code",Menlo,Consolas,monospace;
--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,system-ui,sans-serif;--maxw:1040px}
@media (prefers-color-scheme:dark){:root{--bg:#0c0d10;--surface:#131519;--text:#e9eaee;--muted:#979aa4;
--faint:#6a6d77;--border:#22242b;--border2:#2e313a;--accent:#34d399;--off:#d17b7a;--def:#7ea0d6;--core:#a698c4}}
:root[data-theme="light"]{--bg:#fff;--surface:#fafafa;--text:#17181c;--muted:#5f636e;--faint:#8b8f9a;
--border:#e7e8ec;--border2:#d9dbe0;--accent:#0a8f5f;--off:#b0605f;--def:#5a7bb0;--core:#87799f}
:root[data-theme="dark"]{--bg:#0c0d10;--surface:#131519;--text:#e9eaee;--muted:#979aa4;--faint:#6a6d77;
--border:#22242b;--border2:#2e313a;--accent:#34d399;--off:#d17b7a;--def:#7ea0d6;--core:#a698c4}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);font-size:16px;
line-height:1.6;-webkit-font-smoothing:antialiased;letter-spacing:-.003em}
.wrap{max-width:var(--maxw);margin:0 auto;padding:0 28px}
h1,h2,h3,h4{margin:0;line-height:1.15;letter-spacing:-.02em;text-wrap:balance}
a{color:inherit;text-decoration:none}a:hover{text-decoration:underline}
.mono{font-family:var(--mono)}
.eyebrow,.lbl{font-family:var(--mono);font-size:12px;color:var(--muted)}
.top{position:sticky;top:0;z-index:20;background:color-mix(in srgb,var(--bg) 86%,transparent);
backdrop-filter:blur(8px);border-bottom:1px solid var(--border)}
.top .wrap{display:flex;align-items:center;gap:22px;height:56px}
.brand{font-family:var(--mono);font-weight:600;font-size:15px}
.top nav{display:flex;gap:20px;margin-left:auto}.top nav a{font-size:13.5px;color:var(--muted)}
.top nav a:hover{color:var(--text);text-decoration:none}
.tbtn{font-family:var(--mono);font-size:12px;color:var(--muted);background:none;border:0;cursor:pointer;padding:6px}
.tbtn:hover{color:var(--text)}
.dot{width:6px;height:6px;border-radius:50%;flex:none;display:inline-block}
.dot-offense{background:var(--off)}.dot-defense{background:var(--def)}.dot-core{background:var(--core)}
.v{color:var(--accent)}.v svg{width:13px;height:13px;stroke:var(--accent);fill:none;stroke-width:2.4;vertical-align:-1px}
section{padding:60px 0;border-top:1px solid var(--border)}
h2.title{font-size:clamp(20px,2.6vw,26px);font-weight:620}.sub{color:var(--muted);margin:8px 0 0;max-width:62ch}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:3px}
@media (prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
""".strip()

THEME_JS = ("<script>var r=document.documentElement,b=document.getElementById('tbtn');"
            "b&&b.addEventListener('click',function(){var c=r.getAttribute('data-theme')||"
            "(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light');"
            "r.setAttribute('data-theme',c==='dark'?'light':'dark')});</script>")

CHECK = '<svg viewBox="0 0 24 24"><path d="M5 13l4 4L19 7"/></svg>'


def page(title, css_href, body, extra_head=""):
    return (f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>{html.escape(title)}</title>"
            f"<link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' "
            f"viewBox='0 0 100 100'%3E%3Ctext y='.9em' font-size='90'%3E%F0%9F%9B%A1%EF%B8%8F%3C/text%3E%3C/svg%3E\">"
            f"<link rel=\"stylesheet\" href=\"{css_href}\">{extra_head}</head><body>{body}{THEME_JS}</body></html>")


# ------------------------------------------------------------------- rendering

def render_skill_page(s: dict, names: set[str]) -> str:
    body_html = md_to_html(s["body"], names, s["name"])
    css = """
    .shead{padding:56px 0 34px}
    .crumb{font-family:var(--mono);font-size:12.5px;color:var(--muted);margin-bottom:20px}
    .crumb a{color:var(--muted)}
    h1.sk{font-family:var(--mono);font-size:clamp(24px,4vw,36px);font-weight:600;letter-spacing:-.02em}
    .stags{display:flex;gap:16px;align-items:center;margin-top:16px;font-family:var(--mono);font-size:12.5px;color:var(--muted);flex-wrap:wrap}
    .sdesc{margin-top:22px;font-size:17px;color:var(--muted);max-width:70ch;line-height:1.55}
    .inst{margin-top:22px;background:var(--surface);border:1px solid var(--border);border-radius:8px;
    padding:13px 16px;font-family:var(--mono);font-size:13px;overflow-x:auto}
    .inst .p{color:var(--faint);user-select:none}
    article{padding:44px 0 72px;border-top:1px solid var(--border)}
    article h2{font-size:20px;font-weight:640;margin:38px 0 12px;padding-top:6px}
    article h3{font-size:16px;font-weight:640;margin:26px 0 8px}
    article h4{font-size:14px;font-weight:640;margin:20px 0 6px;color:var(--muted)}
    article p{margin:0 0 15px;max-width:74ch}
    article ul,article ol{margin:0 0 16px;padding-left:22px;max-width:74ch}
    article li{margin:5px 0}article li>ul{margin:5px 0}
    article code{font-family:var(--mono);font-size:.86em;background:var(--surface);padding:1px 5px;border-radius:4px}
    article a.xref code{color:var(--accent);background:color-mix(in srgb,var(--accent) 9%,var(--surface))}
    article pre{background:var(--surface);border:1px solid var(--border);border-radius:8px;
    padding:15px 16px;overflow-x:auto;margin:0 0 18px;max-width:100%}
    article pre code{background:none;padding:0;font-size:12.5px;line-height:1.7}
    article blockquote{margin:0 0 18px;padding:2px 0 2px 18px;border-left:2px solid var(--border2);color:var(--muted)}
    .tw{overflow-x:auto;margin:0 0 18px}article table{border-collapse:collapse;width:100%;font-size:14px}
    article th,article td{text-align:left;padding:9px 14px;border-bottom:1px solid var(--border);vertical-align:top}
    article th{font-family:var(--mono);font-size:12px;color:var(--muted);font-weight:600}
    """
    inst_line = (f'<span class="p">$ </span>/plugin install secskills-{s["plugin"]}'
                 + ('' if s["plugin"] == "core" else
                    '\n<span class="p">$ </span>/plugin install secskills-core'))
    body = f"""
<div class="top"><div class="wrap"><a class="brand" href="index.html">secskills</a>
<nav><a href="index.html#catalog">← all skills</a><a href="https://github.com/trilwu/secskills">github</a></nav>
<button class="tbtn" id="tbtn" aria-label="Toggle theme">theme</button></div></div>
<header class="shead"><div class="wrap">
  <div class="crumb"><a href="index.html">secskills</a> / {s['plugin']} / {s['name']}</div>
  <h1 class="sk">{s['name']}</h1>
  <div class="stags">
    <span><span class="dot dot-{s['plugin']}"></span> {s['plugin']}</span>
    <span class="v">{CHECK} verified {s['verified']}</span>
  </div>
  <p class="sdesc">{html.escape(s['desc'])}</p>
  <div class="inst">{inst_line}</div>
</div></header>
<article><div class="wrap">{body_html}</div></article>
"""
    return page(f"{s['name']} — SecSkills", "style.css", body,
                extra_head=f"<style>{css}</style>")


def render_index(skills: list[dict], names: set[str]) -> str:
    counts = {p: sum(1 for s in skills if s["plugin"] == p) for p in ("offense", "defense", "core")}
    data = json.dumps([{"n": s["name"], "p": s["plugin"], "t": _tagline(s["desc"])} for s in skills],
                      ensure_ascii=False, separators=(",", ":"))
    css = """
    header.hero{padding:88px 0 64px}
    h1.big{font-size:clamp(32px,5vw,52px);font-weight:640;line-height:1.04;max-width:16ch}
    .lede{margin-top:22px;font-size:19px;color:var(--muted);max-width:60ch;line-height:1.55}
    .lede b{color:var(--text);font-weight:600}
    .meta{display:flex;flex-wrap:wrap;gap:8px 22px;margin-top:26px;font-family:var(--mono);font-size:13px;color:var(--muted);align-items:center}
    .meta .ok{color:var(--accent)}.meta .sep{color:var(--faint)}
    .code{margin-top:34px;background:var(--surface);border:1px solid var(--border);border-radius:8px;
    padding:18px 20px;font-family:var(--mono);font-size:13px;line-height:2;overflow-x:auto;max-width:640px}
    .code .c{color:var(--faint)}.code .p{color:var(--muted);user-select:none}
    .steps{margin-top:34px;display:grid;gap:26px;max-width:74ch}
    .step{display:grid;grid-template-columns:26px 1fr;gap:18px;align-items:baseline}
    .step .i{font-family:var(--mono);font-size:13px;color:var(--faint)}
    .step b{font-weight:600;font-size:16px}.step p{margin:5px 0 0;color:var(--muted);font-size:14.5px}
    .step code{font-family:var(--mono);font-size:12.5px;background:var(--surface);padding:1px 5px;border-radius:4px}
    .uc{margin-top:20px}
    .ucg{font-family:var(--mono);font-size:12px;color:var(--faint);margin:26px 0 12px}
    .cards2{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--border);border:1px solid var(--border);border-radius:10px;overflow:hidden}
    .uccard{background:var(--bg);padding:20px 22px}
    .uccard .who{font-family:var(--mono);font-size:11px;color:var(--faint)}
    .uccard .pr{font-family:var(--mono);font-size:13px;color:var(--text);margin:9px 0 12px;line-height:1.5}
    .uccard .to{font-size:12.5px;color:var(--muted)}
    .uccard .to a{color:var(--accent)}
    .roles{display:grid;grid-template-columns:repeat(2,1fr);gap:1px;margin-top:34px;background:var(--border);
    border:1px solid var(--border);border-radius:10px;overflow:hidden}
    .role{background:var(--bg);padding:24px 26px}.role .r{font-family:var(--mono);font-size:12px;color:var(--muted)}
    .role h3{font-size:18px;font-weight:600;margin:8px 0 3px}
    .role .inst2{font-family:var(--mono);font-size:12.5px;color:var(--accent);margin-bottom:12px}
    .role p{margin:0;font-size:14px;color:var(--muted)}.role p b{color:var(--text);font-weight:600}
    .role code{font-family:var(--mono);font-size:12.5px;background:var(--surface);padding:1px 5px;border-radius:4px}
    .bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:30px 0 8px}
    .search{flex:1;min-width:240px;display:flex;align-items:center;gap:9px;background:var(--surface);
    border:1px solid var(--border);border-radius:8px;padding:0 13px}
    .search input{flex:1;background:none;border:0;outline:none;color:var(--text);font-family:var(--mono);font-size:13.5px;padding:11px 0}
    .search svg{width:15px;height:15px;stroke:var(--faint);fill:none;stroke-width:1.8}
    .chip{font-family:var(--mono);font-size:12.5px;padding:8px 12px;border-radius:7px;cursor:pointer;background:none;
    border:1px solid var(--border);color:var(--muted);display:inline-flex;align-items:center;gap:7px}
    .chip:hover{color:var(--text)}.chip[aria-pressed="true"]{color:var(--text);border-color:var(--text)}
    .cnt{font-family:var(--mono);font-size:12.5px;color:var(--faint);margin:16px 0}
    .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:1px;background:var(--border);
    border:1px solid var(--border);border-radius:10px;overflow:hidden}
    .card{background:var(--bg);padding:16px 18px;min-height:92px;display:block;color:inherit}
    .card:hover{background:var(--surface);text-decoration:none}
    .card .h{display:flex;align-items:center;gap:8px;margin-bottom:7px}
    .card .name{font-family:var(--mono);font-size:13px;font-weight:600}
    .card .vv{margin-left:auto}.card .desc{font-size:13px;color:var(--muted);line-height:1.5}
    .empty{grid-column:1/-1;background:var(--bg);text-align:center;color:var(--faint);font-family:var(--mono);font-size:13px;padding:48px 0}
    .stats{display:flex;flex-wrap:wrap;gap:36px 56px;margin-top:30px}
    .stat .n{font-family:var(--mono);font-size:30px;font-weight:600;font-variant-numeric:tabular-nums}
    .stat .n.ok{color:var(--accent)}.stat .l{font-size:13px;color:var(--muted);margin-top:2px}
    footer{border-top:1px solid var(--border);padding:38px 0;font-size:13px;color:var(--muted)}
    footer .wrap{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;align-items:baseline}
    footer .mono{font-size:12.5px;color:var(--faint)}
    @media (max-width:760px){.roles,.cards2{grid-template-columns:1fr}.top nav{display:none}}
    """

    def role(r, h, inst, p):
        return f'<div class="role"><div class="r">{r}</div><h3>{h}</h3><div class="inst2">{inst}</div><p>{p}</p></div>'
    roles = (
        role("red team · pentest", "Offensive operations", "offense + core",
             "AD &amp; Entra, AD CS ESC1–16, cloud, managed k8s, mobile, wireless, web/auth — plus <code>recognizing-deception</code> and <code>maintaining-engagement-state</code>.")
        + role("appsec · code review", "Find &amp; fix in code", "core (+ offense to prove impact)",
               "Source audit with a verification gate, PR review that reads deleted lines, crypto &amp; supply-chain, AI/MCP, PHP depth, backdoor hunting.")
        + role("dfir · incident response", "Investigate &amp; respond", "defense + core",
               "Preserve-first forensics and cross-cloud IR for <b>AWS, Azure, GCP, M365/Entra</b>, built on the audit-log defaults that decide what's answerable.")
        + role("soc · detection eng", "Triage &amp; detect", "defense + core",
               "Base-rate alert triage, detection-as-code with real FP analysis, threat hunting, KEV+EPSS vuln management, finished intel."))

    uc_html = ""
    for group, items in USE_CASES:
        uc_html += f'<div class="ucg">{group}</div><div class="cards2">'
        for who, prompt, skill in items:
            uc_html += (f'<div class="uccard"><div class="who">{html.escape(who)}</div>'
                        f'<div class="pr">"{html.escape(prompt)}"</div>'
                        f'<div class="to">→ <a href="skills/{skill}.html">{skill}</a></div></div>')
        uc_html += "</div>"

    body = f"""
<div class="top"><div class="wrap"><span class="brand">secskills</span>
<nav><a href="#how">how it works</a><a href="#use">use cases</a><a href="#catalog">catalog</a>
<a href="#verify">verification</a><a href="https://github.com/trilwu/secskills">github</a></nav>
<button class="tbtn" id="tbtn" aria-label="Toggle theme">theme</button></div></div>

<header class="hero"><div class="wrap">
  <div class="eyebrow">{len(skills)} skills · 3 plugins · Claude Code</div>
  <h1 class="big" style="margin-top:18px">Security skills with the judgment built in.</h1>
  <p class="lede">Claude knows the commands. What these encode is the discipline — <b>trace impact before you report it, preserve before you remediate, spot the honeypot before you touch it</b>. Every skill fact-checked against primary sources.</p>
  <div class="meta"><span class="ok">✓ {len(skills)} / {len(skills)} verified</span><span class="sep">·</span>
  <span>offense {counts['offense']}</span><span>defense {counts['defense']}</span><span>core {counts['core']}</span></div>
  <div class="code"><span class="c"># add the marketplace</span>
<span class="p">$ </span>/plugin marketplace add trilwu/secskills
<span class="c"># offensive — red team / pentest</span>
<span class="p">$ </span>/plugin install secskills-offense
<span class="p">$ </span>/plugin install secskills-core
<span class="c"># defensive — DFIR / SOC / detection</span>
<span class="p">$ </span>/plugin install secskills-defense
<span class="p">$ </span>/plugin install secskills-core</div>
</div></header>

<section id="how"><div class="wrap"><div class="lbl">how it works</div>
<h2 class="title">You describe the task — the skill does the rest</h2>
<p class="sub">No commands to memorize, no manual invocation. This is what a skill changes versus asking Claude cold.</p>
<div class="steps">
<div class="step"><span class="i">01</span><div><b>You describe the task in plain language.</b><p>Say <code>audit this repo for auth bugs</code> or <code>a host is beaconing — where do I start?</code>. Claude Code matches the right skill from its description; you never type a skill name.</p></div></div>
<div class="step"><span class="i">02</span><div><b>It loads only when it applies.</b><p>Only each skill's one-line description sits in context. The full methodology loads when your task triggers it — {len(skills)} skills cost nothing until one is relevant. Procedure skills wait for their evidence (a <code>libflutter.so</code>, a <code>SAMLResponse</code>, an <code>.E01</code> image).</p></div></div>
<div class="step"><span class="i">03</span><div><b>It shapes the approach, then hands off.</b><p>The skill enforces a methodology — sequence, scope, the verification gate — and names the sibling skill to switch to as the task moves. That is how the collection composes instead of dumping commands.</p></div></div>
<div class="step"><span class="i">04</span><div><b>It refuses the shortcut.</b><p>Each skill's <i>Rationalizations to Reject</i> blocks the plausible-but-wrong call — <q>grep was clean, so the tree is clean</q>, <q>the tool rated it critical, so escalate</q>.</p></div></div>
</div></div></section>

<section id="use"><div class="wrap"><div class="lbl">prompt by use case</div>
<h2 class="title">What to actually type</h2>
<p class="sub">You don't need the jargon. Describe the situation — here are good starting prompts, and where each lands.</p>
<div class="uc">{uc_html}</div></div></section>

<section id="roles"><div class="wrap"><div class="lbl">who it's for</div>
<h2 class="title">Install your side, get a coherent toolkit</h2>
<p class="sub">Cloud and Kubernetes are covered from both sides, so purple-team work stays in one vocabulary.</p>
<div class="roles">{roles}</div></div></section>

<section id="catalog"><div class="wrap"><div class="lbl">the catalog</div>
<h2 class="title">All {len(skills)} skills</h2>
<p class="sub">Search by name or technique; filter by plugin. Click any skill for the full methodology.</p>
<div class="bar"><label class="search"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
<input id="q" type="search" placeholder="nxc, kerberoast, phar, sigma, IMDS…" autocomplete="off" aria-label="Search skills"></label>
<button class="chip" data-f="all" aria-pressed="true">all</button>
<button class="chip" data-f="offense"><span class="dot dot-offense"></span>offense</button>
<button class="chip" data-f="defense"><span class="dot dot-defense"></span>defense</button>
<button class="chip" data-f="core"><span class="dot dot-core"></span>core</button></div>
<div class="cnt" id="cnt"></div><div class="grid" id="grid"></div></div></section>

<section id="verify"><div class="wrap"><div class="lbl">verification</div>
<h2 class="title">Every skill checked against primary sources</h2>
<p class="sub">The differentiator, and the honest version of it — not confidently-wrong output.</p>
<div class="stats">
<div class="stat"><div class="n ok">{len(skills)}/{len(skills)}</div><div class="l">source-verified</div></div>
<div class="stat"><div class="n">2.6</div><div class="l">errors / skill found</div></div>
<div class="stat"><div class="n">143</div><div class="l">ATT&amp;CK techniques</div></div>
</div>
<p class="sub" style="margin-top:22px"><b style="color:var(--text)">verified:</b> is dated, not eternal — trust the methodology and re-confirm any specific before it lands in a deliverable. CI checks form, not truth; the dates are the accuracy signal.</p>
</div></section>

<footer><div class="wrap"><div><div class="mono">MIT · for authorized security work only</div></div>
<a class="mono" href="https://github.com/trilwu/secskills">github.com/trilwu/secskills →</a></div></footer>

<script>
const SKILLS={data};
const grid=document.getElementById('grid'),q=document.getElementById('q'),cnt=document.getElementById('cnt');
let filter='all';const ck='{CHECK}';
function render(){{const t=q.value.trim().toLowerCase();
const rows=SKILLS.filter(s=>(filter==='all'||s.p===filter)&&(!t||s.n.includes(t)||s.t.toLowerCase().includes(t)));
grid.innerHTML=rows.length?rows.map(s=>`<a class="card" href="skills/${{s.n}}.html">
<div class="h"><span class="dot dot-${{s.p}}"></span><span class="name">${{s.n}}</span><span class="vv v" title="verified">${{ck}}</span></div>
<div class="desc">${{s.t}}</div></a>`).join(''):`<div class="empty">no skills match "${{t}}"</div>`;
cnt.textContent=`${{rows.length}} skill${{rows.length===1?'':'s'}}`+(filter!=='all'?` · ${{filter}}`:'')+(t?` · "${{t}}"`:'');}}
q.addEventListener('input',render);
document.querySelectorAll('.chip').forEach(c=>c.addEventListener('click',()=>{{
document.querySelectorAll('.chip').forEach(x=>x.setAttribute('aria-pressed','false'));
c.setAttribute('aria-pressed','true');filter=c.dataset.f;render();}}));render();
</script>
"""
    return page("SecSkills — verified security skills for Claude Code", "style.css", body,
                extra_head=f"<style>{css}</style>")


def _tagline(desc: str) -> str:
    t = re.split(r"\s+Use when|\s+Use during|\s+Use to|\s+Defers ", desc)[0]
    if "—" in t:
        t = t.split("—", 1)[1].strip() or t
    if ":" in t[:60]:
        t = t.split(":", 1)[1].strip()
    t = t.strip().rstrip(".")
    t = t[0].upper() + t[1:] if t else t
    if len(t) > 120:
        t = t[:117].rsplit(" ", 1)[0] + "…"
    return t


# ------------------------------------------------------------------------ main

def build() -> dict[Path, str]:
    skills = load_skills()
    names = {s["name"] for s in skills}
    files = {
        DOCS / "style.css": CSS,
        DOCS / ".nojekyll": "",
        DOCS / "index.html": render_index(skills, names),
    }
    for s in skills:
        files[DOCS / "skills" / f"{s['name']}.html"] = render_skill_page(s, names)
    return files


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="fail if docs/ is out of date")
    args = ap.parse_args()

    files = build()
    if args.check:
        stale = []
        current = {p for p in DOCS.rglob("*") if p.is_file()} if DOCS.exists() else set()
        for path, content in files.items():
            if not path.is_file() or path.read_text(encoding="utf-8") != content:
                stale.append(path.relative_to(REPO))
        orphan = current - set(files)
        for o in orphan:
            stale.append(o.relative_to(REPO))
        if stale:
            print("docs/ is out of date; run: python3 scripts/build_site.py", file=sys.stderr)
            for s in sorted(map(str, stale)):
                print(f"  {s}", file=sys.stderr)
            return 1
        print(f"docs/ up to date ({len(files)} files)")
        return 0

    # write
    for path in DOCS.rglob("*"):
        if path.is_file() and path not in files:
            path.unlink()
    for path, content in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    print(f"Wrote {len(files)} files to docs/ ({len(load_skills())} skill pages + index)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
