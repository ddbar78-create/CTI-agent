"""
Källkatalog — statistik över deepdarkCTI (github.com/fastfire/deepdarkCTI), en
öppen samling av källor i deep/dark web.

Agenten läser repots markdown-tabeller en gång per dygn och räknar hur många
källor som finns per kategori och hur många som är ONLINE respektive OFFLINE.
BARA antal sparas och visas. Inga adresser, kanalnamn eller innehåll kopieras till
ditt repo eller din panel, utan panelen länkar till repot. Det håller
licensfrågan enkel (repot är GPL-3.0) och undviker att återpublicera länkar till
kriminella marknader och stöldkanaler.

Uppdateras högst en gång per dygn. En fil som inte går att hämta (bytt namn i
repot) hoppas över och noteras i panelen.
"""

import html
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import requests

from storage import DB_PATH

RAW = "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/{name}"
REPO = "https://github.com/fastfire/deepdarkCTI"
TIMEOUT = 40

# fil -> visningsnamn
CATEGORIES = [
    ("ransomware_gang.md", "Ransomware-grupper och spårare"),
    ("maas.md", "Malware-as-a-service"),
    ("forum.md", "Forum"),
    ("markets.md", "Marknadsplatser"),
    ("telegram_threat_actors.md", "Telegram: hotaktörer"),
    ("telegram_infostealer.md", "Telegram: infostealer-kanaler"),
    ("discord.md", "Discord"),
    ("twitter_threat_actors.md", "X/Twitter: hotaktörer"),
    ("exploits.md", "Exploit-källor"),
    ("malware_samples.md", "Malware-prover"),
    ("rat.md", "RAT-verktyg"),
    ("phishing.md", "Phishing"),
    ("defacement.md", "Defacement"),
]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS catalog_stats (
    day TEXT NOT NULL,
    category TEXT NOT NULL,
    total INTEGER NOT NULL DEFAULT 0,
    online INTEGER NOT NULL DEFAULT 0,
    offline INTEGER NOT NULL DEFAULT 0,
    other INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, category)
)
"""


def _connect(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute(_SCHEMA)
    return conn


def _cells(line: str) -> list:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def classify_status(text: str) -> str:
    t = re.sub(r"[^A-Za-z ]", " ", text or "").strip().upper()
    if t.startswith("ONLINE") or t.startswith("VALID"):
        return "online"
    if t.startswith("OFFLINE") or t.startswith("EXPIRED") or t.startswith("DOWN") or "SEIZED" in t or "SIEZED" in t:
        return "offline"
    return "other"


def count_table(markdown: str) -> dict:
    """Räknar rader per status i markdown-tabeller. Statuskolumnen hittas via rubriken 'Status'."""
    total = online = offline = other = 0
    status_idx = None
    for line in markdown.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = _cells(s)
        if all(re.fullmatch(r":?-{2,}:?", c) or not c for c in cells):
            continue  # skiljelinjen
        lowered = [c.lower() for c in cells]
        if "status" in lowered:  # rubrikrad
            status_idx = lowered.index("status")
            continue
        if status_idx is None or status_idx >= len(cells):
            continue
        if not any(cells):
            continue
        if not cells[status_idx]:
            continue  # rad utan status (trasig eller tom)
        total += 1
        kind = classify_status(cells[status_idx])
        if kind == "online":
            online += 1
        elif kind == "offline":
            offline += 1
        else:
            other += 1
    return {"total": total, "online": online, "offline": offline, "other": other}


def run_source_catalog(db_path: str = DB_PATH, force: bool = False) -> int:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    conn = _connect(db_path)
    done = conn.execute("SELECT COUNT(*) FROM catalog_stats WHERE day = ?", (today,)).fetchone()[0]
    conn.close()
    if done and not force:
        print("[+] Källkatalog: redan uppdaterad idag, hoppar över.")
        return 0

    print("[+] Källkatalog: räknar källor i deepdarkCTI ...")
    rows, missing = [], []
    for fname, label in CATEGORIES:
        try:
            resp = requests.get(RAW.format(name=fname), timeout=TIMEOUT, headers={"User-Agent": "cti-agent"})
            if resp.status_code == 404:
                missing.append(fname)
                continue
            resp.raise_for_status()
            c = count_table(resp.text)
            if c["total"]:
                rows.append((today, label, c["total"], c["online"], c["offline"], c["other"]))
        except Exception as e:
            print(f"    {fname}: kunde inte hämtas ({e})", file=sys.stderr)
            missing.append(fname)

    if not rows:
        raise RuntimeError("inga kategorier kunde läsas från deepdarkCTI")
    conn = _connect(db_path)
    conn.executemany(
        """
        INSERT INTO catalog_stats (day, category, total, online, offline, other) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(day, category) DO UPDATE SET total=excluded.total, online=excluded.online,
            offline=excluded.offline, other=excluded.other
        """,
        rows,
    )
    cutoff = (datetime.now(timezone.utc) - timedelta(days=60)).strftime("%Y-%m-%d")
    conn.execute("DELETE FROM catalog_stats WHERE day < ?", (cutoff,))
    conn.commit()
    conn.close()
    if missing:
        print("    Källkatalog: hoppade över (saknas eller kunde inte hämtas): " + ", ".join(missing), file=sys.stderr)
    total = sum(r[2] for r in rows)
    print(f"    Källkatalog: {len(rows)} kategorier, {total} källor räknade.")
    return total


# ---------------------------------------------------------------- visning
CATALOG_CSS = """
  .sc-note { font-size: 0.78rem; margin-bottom: 0.8rem; white-space: normal; }
  .sc-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  .sc-table th { text-align: left; font-weight: 500; color: var(--text-dim); font-size: 0.75rem; padding: 0.3rem 0.5rem; border-bottom: 1px solid var(--panel-border); }
  .sc-table td { padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--panel-border); vertical-align: middle; }
  .sc-table td.num { font-family: var(--mono, monospace); text-align: right; white-space: nowrap; }
  .sc-bar { display: inline-block; height: 0.55rem; border-radius: 2px; vertical-align: middle; background: var(--green, #3fb950); opacity: 0.8; }
  .sc-bar.off { background: var(--red); }
  .sc-up { color: var(--green, #3fb950); } .sc-down { color: var(--red); }
"""


def _esc(v) -> str:
    return html.escape(str(v)) if v is not None else ""


def build_source_catalog_html(db_path: str = DB_PATH) -> str:
    conn = _connect(db_path)
    latest = conn.execute("SELECT MAX(day) FROM catalog_stats").fetchone()[0]
    if not latest:
        conn.close()
        return '<p class="empty">Ingen källkatalog ännu, fylls efter nästa körning (se källstatus överst).</p>'
    now = conn.execute(
        "SELECT category, total, online, offline, other FROM catalog_stats WHERE day = ?", (latest,)
    ).fetchall()
    week_ago = (datetime.strptime(latest, "%Y-%m-%d") - timedelta(days=6)).strftime("%Y-%m-%d")
    prev_day = conn.execute("SELECT MAX(day) FROM catalog_stats WHERE day <= ? AND day < ?", (week_ago, latest)).fetchone()[0]
    prev = {}
    if prev_day:
        prev = {r[0]: r[2] for r in conn.execute("SELECT category, total, online FROM catalog_stats WHERE day = ?", (prev_day,))}
    conn.close()

    order = [label for _f, label in CATEGORIES]
    now = sorted(now, key=lambda r: order.index(r[0]) if r[0] in order else 99)
    mx = max((r[1] for r in now), default=1) or 1
    rows = []
    for cat, total, online, offline, other in now:
        w_on = round(online / mx * 140)
        w_off = round((offline + other) / mx * 140)
        delta = ""
        if cat in prev:
            d = online - prev[cat]
            if d:
                delta = f' <span class="{"sc-up" if d > 0 else "sc-down"}">{"+" if d > 0 else ""}{d} online</span>'
        rows.append(
            f"<tr><td>{_esc(cat)}</td><td class=\"num\">{total}</td><td class=\"num\">{online}{delta}</td>"
            f"<td class=\"num\">{offline}</td>"
            f"<td><span class=\"sc-bar\" style=\"width:{w_on}px\"></span>"
            f"<span class=\"sc-bar off\" style=\"width:{w_off}px\"></span></td></tr>"
        )
    sum_total = sum(r[1] for r in now)
    sum_on = sum(r[2] for r in now)
    note = (
        f'<p class="dim sc-note">Antal källor i <a href="{REPO}" target="_blank" rel="noopener">deepdarkCTI</a> '
        f"(GPL-3.0), uppdaterat {_esc(latest)}. Endast antal visas. Adresser och innehåll återpubliceras inte, "
        f"se repot för själva listorna. <b>{sum_on} av {sum_total}</b> källor är ONLINE. "
        f"Förändring jämförs med {_esc(prev_day) if prev_day else 'första mätningen (jämförelse saknas ännu)'}.</p>"
    )
    return (
        note + '<table class="sc-table"><tr><th>Kategori</th><th>Totalt</th><th>Online</th><th>Offline</th>'
        "<th>Andel online (grönt) och offline/övrigt (rött)</th></tr>" + "".join(rows) + "</table>"
    )


if __name__ == "__main__":
    run_source_catalog(force=True)
