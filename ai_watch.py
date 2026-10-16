"""
AI-hot — bevakning av hot som rör AI, utan LLM och utan nya nycklar.

Skannar redan insamlade artiklar (RSS/Telegram/OTX) och CVE-data efter
nyckelord i fyra kategorier:

  1. Angrepp som använder AI          (deepfakes, röstkloning, AI-phishing, AI-skapad malware)
  2. Angrepp mot AI-system            (prompt injection, jailbreak, dataförgiftning, modellstöld)
  3. AI-agenter, MCP och AI-verktyg   (MCP-servrar, agenter, Ollama, LangChain, ComfyUI m.fl. + CVE:er)
  4. Skadliga modeller / leveranskedja (trojaniserade modeller, slopsquatting, Hugging Face)

Plus en informationsrad om ramverk (MITRE ATLAS, OWASP LLM Top 10). Ren
nyckelordsmatchning: kontrollera alltid träffen. Redigera TERMS nedan för att
lägga till eller ta bort ord.
"""

import html
import re
import sqlite3

from storage import DB_PATH

WINDOW_DAYS = 30
MAX_ARTICLES_SCANNED = 2000

# Varje kategori: (id, namn, förklaring, [termer]). Termer matchas som hela ord/fraser,
# skiftlägesokänsligt. Håll dem specifika, "AI" ensamt ger för mycket brus.
CATEGORIES = [
    ("use", "Angrepp som använder AI",
     "Hotaktörer som utnyttjar AI för bedrägerier, phishing eller skadlig kod.",
     ["deepfake", "deepfakes", "voice cloning", "cloned voice", "voice clone", "ai-generated phishing",
      "ai-powered phishing", "ai-powered attack", "ai-assisted attack", "ai-enabled attack",
      "ai-generated malware", "llm-powered malware", "ai-written malware", "malicious llm",
      "wormgpt", "fraudgpt", "ai-driven attack", "ai-generated code in attack", "vibe hacking",
      "ai-orchestrated", "autonomous attack", "ai-enabled malware", "synthetic identity",
      "ai voice scam", "generative ai phishing"]),
    ("against", "Angrepp mot AI-system",
     "Manipulation av modeller, prompts och träningsdata.",
     ["prompt injection", "indirect prompt injection", "jailbreak", "jailbreaks", "jailbroken",
      "data poisoning", "model poisoning", "training data poisoning", "model extraction",
      "model inversion", "adversarial example", "adversarial attack", "agent hijacking",
      "tool poisoning", "rules file backdoor", "ai guardrail bypass", "llm vulnerability",
      "ai model backdoor", "sleeper agent", "system prompt leak"]),
    ("tools", "AI-agenter, MCP och AI-verktyg",
     "Sårbarheter och missbruk i agenter, MCP-servrar och populära AI-program.",
     ["mcp server", "mcp servers", "model context protocol", "ai agent", "ai agents", "agentic",
      "copilot", "langchain", "langgraph", "llamaindex", "ollama", "llama.cpp", "vllm", "comfyui",
      "open webui", "openwebui", "n8n", "flowise", "langflow", "gradio", "mlflow", "ray cluster",
      "chatgpt", "claude code", "cursor ide", "github copilot", "ai coding assistant", "ai browser",
      "ai assistant vulnerability", "autogpt", "dify"]),
    ("supply", "Skadliga modeller och AI-leveranskedja",
     "Trojaniserade modeller, förgiftade paket och falska AI-verktyg.",
     ["malicious model", "malicious models", "hugging face", "huggingface", "pickle file", "pickle deserialization",
      "poisoned model", "slopsquatting", "package hallucination", "hallucinated package",
      "fake ai", "fake chatgpt", "fake ai tool", "ai supply chain", "model supply chain", "safetensors",
      "malicious extension ai", "malicious npm ai", "rogue mcp"]),
]

FRAMEWORKS = [
    ("MITRE ATLAS", "https://atlas.mitre.org"),
    ("OWASP Top 10 för LLM-applikationer", "https://genai.owasp.org/llm-top-10/"),
    ("NIST AI Risk Management Framework", "https://www.nist.gov/itl/ai-risk-management-framework"),
]


def _esc(v) -> str:
    return html.escape(str(v)) if v is not None else ""


def _compile(terms: list):
    parts = [r"(?<![a-z0-9])" + re.escape(t.lower()) + r"(?![a-z0-9])" for t in terms if t.strip()]
    return re.compile("|".join(parts), re.I) if parts else None


_COMPILED = [(cid, name, desc, _compile(terms)) for cid, name, desc, terms in CATEGORIES]


def _fetch(conn, query, params=()):
    try:
        cur = conn.execute(query, params)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    except sqlite3.Error:
        return []


def collect_ai_hits(db_path: str = DB_PATH, days: int = WINDOW_DAYS) -> list:
    conn = sqlite3.connect(db_path)
    cves = _fetch(
        conn,
        "SELECT cve_id, cvss, epss, kev, summary FROM cve_enrichment ORDER BY kev DESC, epss DESC",
    )
    arts = _fetch(
        conn,
        """
        SELECT feed, title, link, summary, substr(full_text, 1, 2000) AS full_text, fetched_at
        FROM articles
        WHERE feed != 'ransomware.live' AND feed NOT LIKE 'ThreatFox%'
          AND fetched_at >= datetime('now', ?)
        ORDER BY id DESC LIMIT ?
        """,
        (f"-{int(days)} day", MAX_ARTICLES_SCANNED),
    )
    conn.close()

    out = []
    for cid, name, desc, rx in _COMPILED:
        if not rx:
            continue
        hits = []
        for a in arts:
            text = f"{a['title']} {a['summary'] or ''} {a['full_text'] or ''}"
            m = rx.search(text)
            if m:
                hits.append({**a, "matched": m.group(0).lower()})
        cve_hits = [c for c in cves if rx.search(c["summary"] or "")]
        kev = [c for c in cve_hits if c["kev"]]
        recent = [a for a in hits if a["fetched_at"] and a["fetched_at"] >= _days_ago(7)]
        out.append({
            "id": cid, "name": name, "desc": desc, "articles": hits, "cves": cve_hits,
            "kev": kev, "recent": len(recent),
        })
    return out


def _days_ago(n: int) -> str:
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) - timedelta(days=n)).strftime("%Y-%m-%d %H:%M:%S")


def build_ai_watch_html(db_path: str = DB_PATH) -> str:
    results = collect_ai_hits(db_path)
    total = sum(len(r["articles"]) for r in results)

    cards = []
    for r in results:
        cls = "hot" if r["kev"] else ("warm" if (r["articles"] or r["cves"]) else "")
        badges = []
        if r["kev"]:
            badges.append(f'<span class="badge badge-critical">{len(r["kev"])} KEV-CVE</span>')
        if r["recent"]:
            badges.append(f'<span class="badge badge-high">{r["recent"]} senaste 7 d</span>')
        if r["cves"]:
            badges.append(f'<span class="dim">{len(r["cves"])} CVE</span>')
        badges.append(f'<span class="dim">{len(r["articles"])} artiklar</span>')

        body = [f'<p class="dim" style="white-space:normal">{_esc(r["desc"])}</p>']
        if r["cves"]:
            def _cve_li(c):
                flag = '<span class="badge badge-critical">KEV</span> ' if c["kev"] else ""
                epss = f' <span class="dim">EPSS {c["epss"]:.0%}</span>' if c["epss"] is not None else ""
                return (f'<li class="mono">{flag}{_esc(c["cve_id"])}{epss} '
                        f'<span class="dim" style="font-family:var(--sans)">{_esc((c["summary"] or "")[:130])}</span></li>')
            body.append("<h4>CVE:er</h4><ul>" + "".join(_cve_li(c) for c in r["cves"][:10]) + "</ul>")
        if r["articles"]:
            body.append("<h4>Artiklar</h4><ul>" + "".join(
                f'<li><a href="{_esc(a["link"])}" target="_blank" rel="noopener">{_esc(a["title"])}</a> '
                f'<span class="dim">{_esc(a["feed"])} · träff: {_esc(a["matched"])}</span></li>'
                for a in r["articles"][:12]) + "</ul>")
        else:
            body.append(f'<p class="dim">Inga träffar de senaste {WINDOW_DAYS} dagarna.</p>')

        cards.append(
            f'<details class="tw-card {cls}"{" open" if cls == "hot" else ""}>'
            f'<summary><span class="tw-name">{_esc(r["name"])}</span>{"".join(badges)}</summary>'
            f'<div class="tw-body">{"".join(body)}</div></details>'
        )

    frameworks = " · ".join(
        f'<a href="{_esc(u)}" target="_blank" rel="noopener">{_esc(n)}</a>' for n, u in FRAMEWORKS
    )
    note = (f'<p class="dim tw-note">{total} träffar i artiklar de senaste {WINDOW_DAYS} dagarna. '
            f'Nyckelordsmatchning (se <code>ai_watch.py</code>), kontrollera alltid träffen. '
            f'Ramverk: {frameworks}.</p>')
    return note + "".join(cards)
