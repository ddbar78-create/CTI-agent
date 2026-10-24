"""
Rapporter — månads- och årsrapport (Global Threat Report-stil) och veckobrief för ledning.

Månads- och årsrapport (sektionen "Rapporter"):
  Per månad och kalenderår: antal ransomware-offer och förändring mot föregående period, mest aktiva grupper,
  mest drabbade branscher och länder, nordisk andel, nya grupper, antal nya CISA KEV-poster och, för den
  senaste månaden, mest riskfyllda CVE:er. Regelbaserad text, ingen LLM. Kan laddas ner som Markdown.
  Rapporten täcker så långt tillbaka som ransomware-tabellen räcker.

Veckobrief: byggs en gång per vecka (första körningen efter att ny vecka börjat) som Markdown i reports/
(committas av workflowet) och skickas som mejl om SMTP är inställt (se notifier.py). Fem delar:
  1. Läget  2. Nordiska offer  3. Patcha detta  4. Er attackyta  5. Ändringar sedan förra veckan
Skickas aldrig två gånger för samma vecka (tabellen reports_sent). Misslyckas mejlet, försöker nästa körning igen.
"""

import html
import json
import os
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

from config_org import ORG
from storage import DB_PATH

NORDIC = {"SE", "NO", "DK", "FI", "IS"}
MONTHS_SV = ["januari", "februari", "mars", "april", "maj", "juni", "juli", "augusti", "september", "oktober", "november", "december"]
REPORT_DIR = "reports"

_SCHEMA = "CREATE TABLE IF NOT EXISTS reports_sent (key TEXT PRIMARY KEY, sent_at TEXT, channels TEXT)"


def _connect(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute(_SCHEMA)
    return conn


# ------------------------------------------------------------------ månads- och årsrapport
def _period_stats(victims, kev_titles, since, until):
    vs = [v for v in victims if v["day"] and since <= v["day"] < until]
    return {
        "n": len(vs), "nordic": sum(1 for v in vs if v["cc"] in NORDIC),
        "groups": Counter(v["group"] for v in vs).most_common(5),
        "sectors": Counter(v["sector"] for v in vs if v["sector"]).most_common(5),
        "countries": Counter(v["cc"] for v in vs if v["cc"]).most_common(5),
        "group_set": {v["group"] for v in vs},
    }


def report_markdown(ctx, label, since, until, prev_since, prev_until, kev_count, top_cves=None) -> str:
    victims = ctx["victims"]
    cur = _period_stats(victims, [], since, until)
    prev = _period_stats(victims, [], prev_since, prev_until)
    before = {v["group"] for v in victims if v["day"] and v["day"] < since}
    new_groups = sorted(cur["group_set"] - before)
    delta = cur["n"] - prev["n"]
    pct = f" ({delta / prev['n']:+.0%})" if prev["n"] else ""
    share = f"{cur['nordic'] / cur['n']:.0%}" if cur["n"] else "0%"
    md = [f"# Hotrapport {label}", "",
          f"Under perioden registrerades **{cur['n']} ransomware-offer** (föregående period: {prev['n']}, "
          f"{'ingen förändring' if delta == 0 else ('upp ' if delta > 0 else 'ned ') + str(abs(delta))}{pct}). "
          f"{cur['nordic']} av dem ({share}) var nordiska.", ""]
    if cur["groups"]:
        md += ["## Mest aktiva grupper", ""] + [f"- {g}: {c}" for g, c in cur["groups"]] + [""]
    if cur["sectors"]:
        md += ["## Mest drabbade branscher", ""] + [f"- {s}: {c}" for s, c in cur["sectors"]] + [""]
    if cur["countries"]:
        md += ["## Mest drabbade länder", ""] + [f"- {c}: {n}" for c, n in cur["countries"]] + [""]
    md += ["## Övrigt", "", f"- Nya grupper (första offer i perioden): {', '.join(new_groups[:10]) if new_groups else 'inga'}",
           f"- Nya poster i CISA KEV: {kev_count}"]
    if top_cves:
        md += ["", "## Mest riskfyllda sårbarheter", ""] + [f"- {c['id']} (risk {c['score']})" for c in top_cves]
    return "\n".join(md)


def _md_to_html(md: str) -> str:
    out, in_list = [], False
    for line in md.splitlines():
        if line.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline(line[2:])}</li>")
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        if line.startswith("# "):
            out.append(f"<h3>{_inline(line[2:])}</h3>")
        elif line.startswith("## "):
            out.append(f"<h4>{_inline(line[3:])}</h4>")
        elif line.strip():
            out.append(f"<p>{_inline(line)}</p>")
    if in_list:
        out.append("</ul>")
    return "".join(out)


def _inline(s: str) -> str:
    s = html.escape(s)
    import re
    return re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)


def _kev_count(db_path, since, until) -> int:
    try:
        conn = sqlite3.connect(db_path)
        n = conn.execute("SELECT COUNT(*) FROM articles WHERE feed = 'CISA KEV' AND substr(fetched_at,1,10) >= ? AND substr(fetched_at,1,10) < ?",
                         (str(since), str(until))).fetchone()[0]
        conn.close()
        return n
    except sqlite3.Error:
        return 0


def build_report_set(ctx, db_path: str) -> list:
    """[(id, etikett, markdown)] för de senaste 12 månaderna och innevarande år."""
    today = ctx["today"]
    days = [v["day"] for v in ctx["victims"] if v["day"]]
    if not days:
        return []
    out = []
    y, m = today.year, today.month
    for _ in range(12):
        since = datetime(y, m, 1).date()
        until = datetime(y + (m == 12), (m % 12) + 1, 1).date()
        py, pm = (y - 1, 12) if m == 1 else (y, m - 1)
        prev_since = datetime(py, pm, 1).date()
        if until > min(days) and since <= max(days):
            top = ctx["cves"][:5] if (y, m) == (today.year, today.month) else None
            out.append((f"{y}-{m:02d}", f"{MONTHS_SV[m - 1].capitalize()} {y}",
                        report_markdown(ctx, f"{MONTHS_SV[m - 1]} {y}", since, until, prev_since, since, _kev_count(db_path, since, until), top)))
        y, m = py, pm
    y0 = today.year
    since, until = datetime(y0, 1, 1).date(), datetime(y0 + 1, 1, 1).date()
    out.append((f"{y0}", f"Hela {y0} (hittills)",
                report_markdown(ctx, f"{y0} (hittills)", since, until, datetime(y0 - 1, 1, 1).date(), since, _kev_count(db_path, since, until))))
    return out


REPORTS_CSS = """
  .rp-bar { display: flex; gap: 0.6rem; align-items: center; margin-bottom: 0.8rem; flex-wrap: wrap; }
  .rp-bar select, .rp-bar button { background: var(--panel); color: var(--text); border: 1px solid var(--panel-border); border-radius: 6px; padding: 0.35rem 0.7rem; font-size: 0.82rem; font-family: inherit; cursor: pointer; }
  #rpOut { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 6px; padding: 0.8rem 1.2rem; font-size: 0.86rem; white-space: normal; }
  #rpOut h3 { margin: 0 0 0.5rem; } #rpOut h4 { margin: 0.9rem 0 0.25rem; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-dim); }
  #rpOut ul { margin: 0.2rem 0; padding-left: 1.2rem; } #rpOut p { margin: 0.3rem 0; }
"""


def build_reports_html(ctx, db_path: str = DB_PATH) -> str:
    reps = build_report_set(ctx, db_path)
    if not reps:
        return '<p class="empty">Ingen offerdata ännu, rapporterna fylls när ransomware-offer har samlats in.</p>'
    data = json.dumps([{"id": i, "label": l, "md": md, "html": _md_to_html(md)} for i, l, md in reps], ensure_ascii=False).replace("</", "<\\/")
    opts = "".join(f'<option value="{html.escape(i)}">{html.escape(l)}</option>' for i, l, _m in reps)
    return (
        f'<div class="rp-bar"><label class="dim" for="rpSel">Period:</label><select id="rpSel">{opts}</select>'
        '<button type="button" id="rpDl">Ladda ner som Markdown</button></div><div id="rpOut"></div>'
        "<script>(function(){var R=" + data + ";var sel=document.getElementById('rpSel'),out=document.getElementById('rpOut');"
        "function show(){var r=R.filter(function(x){return x.id===sel.value})[0];out.innerHTML=r?r.html:''}"
        "sel.addEventListener('change',show);"
        "document.getElementById('rpDl').addEventListener('click',function(){var r=R.filter(function(x){return x.id===sel.value})[0];if(!r)return;"
        "var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([r.md],{type:'text/markdown'}));a.download='hotrapport-'+r.id+'.md';"
        "document.body.appendChild(a);a.click();a.remove();});show();})();</script>"
        '<p class="dim" style="font-size:0.78rem;white-space:normal;margin-top:0.6rem">Regelbaserade sammanfattningar av insamlad data. Perioder före första körningen saknas, och '
        'siffrorna beror på vad källorna hunnit publicera.</p>')


# ------------------------------------------------------------------ veckobrief
def build_weekly_brief(ctx, db_path: str = DB_PATH) -> tuple:
    """Returnerar (ämne, markdown). Byggs av samma regelbaserade delar som panelen."""
    from intel import compute_alerts
    from org_profile import compute_profile
    today = ctx["today"]
    iso = today.isocalendar()
    v = [x for x in ctx["victims"] if x["day"]]
    w0 = [x for x in v if 0 <= (today - x["day"]).days < 7]
    w1 = [x for x in v if 7 <= (today - x["day"]).days < 14]
    n0 = sorted([x for x in w0 if x["cc"] in NORDIC], key=lambda x: x["day"], reverse=True)
    groups = Counter(x["group"] for x in w0).most_common(3)
    delta = len(w0) - len(w1)
    profile = compute_profile(ctx)
    alerts = compute_alerts(db_path, ctx)

    md = [f"# Veckobrief {ORG['name']}, vecka {iso[1]} {iso[0]}", "",
          "## 1. Läget", "",
          f"- {len(w0)} ransomware-offer senaste veckan globalt ({'oförändrat' if delta == 0 else ('upp ' if delta > 0 else 'ned ') + str(abs(delta))} mot veckan innan).",
          f"- Mest aktiva: {', '.join(f'{g} ({c})' for g, c in groups) if groups else 'ingen särskild'}.",
          f"- {len(n0)} nordiska offer.", "",
          "## 2. Nordiska offer", ""]
    md += [f"- {x['victim']} ({x['cc']}, {x['day']}) – {x['group']}" for x in n0[:10]] or ["- Inga nordiska offer denna vecka."]
    md += ["", "## 3. Patcha detta", ""]
    md += [f"- {c['id']} (relevans {c['score']}): {'; '.join(c['reasons'][:2])}" for c in profile["cves"][:5]] or ["- Inga sårbarheter med hög relevans just nu."]
    md += ["", "## 4. Er attackyta", ""]
    try:
        conn = sqlite3.connect(db_path)
        crit = conn.execute("SELECT level, title FROM surface_findings WHERE status = 'öppen' ORDER BY CASE level WHEN 'Kritisk' THEN 0 WHEN 'Hög' THEN 1 ELSE 2 END LIMIT 5").fetchall()
        total = conn.execute("SELECT COUNT(*) FROM surface_findings WHERE status = 'öppen'").fetchone()[0]
        la = conn.execute("SELECT domain, score FROM lookalike_domains WHERE score >= 60 ORDER BY score DESC LIMIT 5").fetchall()
        conn.close()
        md += [f"- {total} öppna fynd på attackytan." if total else "- Inga öppna fynd på attackytan."]
        md += [f"  - [{l}] {t}" for l, t in crit]
        md += [f"- Look-alike-domäner med hög poäng: {', '.join(f'{d} ({s})' for d, s in la)}." if la else "- Inga look-alike-domäner med hög poäng."]
    except sqlite3.Error:
        md += ["- Attackytan har inte kontrollerats ännu."]
    md += ["", "## 5. Ändringar sedan förra veckan", ""]
    notable = [a for a in alerts if a["kind"] in ("nordic_spike", "group_spike", "new_group", "sector_spike", "profile", "campaign")]
    md += [f"- {a['title']}: {a['detail']}" for a in notable[:8]] or ["- Inga större förändringar."]
    md += ["", f"Panel: {os.environ.get('PANEL_URL', 'https://ddbar78-create.github.io/CTI-agent/')}"]
    return f"Veckobrief {ORG['name']}, vecka {iso[1]}", "\n".join(md)


def run_weekly_brief(db_path: str = DB_PATH, force: bool = False) -> int:
    from intel import shared_context
    ctx = shared_context(db_path)
    iso = ctx["today"].isocalendar()
    key = f"weekly:{iso[0]}-W{iso[1]:02d}"
    conn = _connect(db_path)
    if not force and conn.execute("SELECT 1 FROM reports_sent WHERE key = ?", (key,)).fetchone():
        conn.close()
        print("[+] Veckobrief: redan skapad denna vecka.")
        return 0
    subject, md = build_weekly_brief(ctx, db_path)
    os.makedirs(REPORT_DIR, exist_ok=True)
    path = os.path.join(REPORT_DIR, f"weekly-{iso[0]}-W{iso[1]:02d}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(md + "\n")
    sent = "fil"
    try:
        import notifier
        if notifier.mail_configured():
            notifier.send_mail(subject, md, "<html><body style='font-family:sans-serif'>" + _md_to_html(md) + "</body></html>")
            sent = "fil,mejl"
    except Exception as e:  # mejl misslyckades: försök igen nästa körning, behåll filen
        print(f"    Veckobrief: mejlet misslyckades ({type(e).__name__}: {str(e)[:100]}), försöker igen nästa körning.", file=sys.stderr)
        conn.close()
        return 0
    conn.execute("INSERT OR REPLACE INTO reports_sent (key, sent_at, channels) VALUES (?, ?, ?)",
                 (key, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), sent))
    conn.commit()
    conn.close()
    print(f"[+] Veckobrief: {path} ({sent}).")
    return 1


if __name__ == "__main__":
    run_weekly_brief(force=True)
