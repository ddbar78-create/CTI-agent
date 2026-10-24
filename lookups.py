"""
Enstaka uppslag mot VirusTotal och urlscan.io — snabb kontext för nya indikatorer.

AVSTÄNGD om nycklarna saknas. Aktiveras av secrets VT_API_KEY (hashar) och URLSCAN_API_KEY (domäner).

  VirusTotal  : SHA-256 med hög poäng (ioc_confidence.py) slås upp en gång. Sparas bara en sammanfattning:
                antal motorer som flaggar, hotetikett, första inlämning och filnamn. Aldrig filuppladdning.
                Gratis API: 4 uppslag per minut och 500 per dag, därför max 6 per körning med paus.
  urlscan.io  : domäner med hög poäng söks bland publika skanningar (antal träffar och senaste).
                Inga nya skanningar startas och inga privata skanningar görs.

Varje värde slås upp en gång och cachas i lookup_cache. Observera att VirusTotals och urlscans villkor kan
begränsa hur data får publiceras (VirusTotals gratis-API är för icke-kommersiellt bruk): kontrollera villkoren
innan du slår på funktionen i ett publikt repo. Därför lagras bara det som behövs för visningen.
"""

import html
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone

import requests

from storage import DB_PATH

VT_URL = "https://www.virustotal.com/api/v3/files/{h}"
URLSCAN_URL = "https://urlscan.io/api/v1/search/"
TIMEOUT = 30
VT_PER_RUN = 6
VT_PAUSE = 15.5
URLSCAN_PER_RUN = 10

_SCHEMA = """
CREATE TABLE IF NOT EXISTS lookup_cache (
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    result TEXT,
    checked_at TEXT,
    PRIMARY KEY (kind, value)
)
"""


def _connect(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute(_SCHEMA)
    return conn


def vt_lookup(sha256: str, key: str) -> dict:
    resp = requests.get(VT_URL.format(h=sha256), headers={"x-apikey": key}, timeout=TIMEOUT)
    if resp.status_code == 404:
        return {"unknown": True}
    if resp.status_code == 429:
        raise RuntimeError("VirusTotal: gränsen nådd (429)")
    resp.raise_for_status()
    a = resp.json().get("data", {}).get("attributes", {})
    stats = a.get("last_analysis_stats", {})
    first = a.get("first_submission_date")
    return {
        "malicious": int(stats.get("malicious", 0)), "suspicious": int(stats.get("suspicious", 0)),
        "total": int(sum(v for v in stats.values() if isinstance(v, int))),
        "label": (a.get("popular_threat_classification") or {}).get("suggested_threat_label", ""),
        "first": datetime.fromtimestamp(first, timezone.utc).strftime("%Y-%m-%d") if isinstance(first, (int, float)) else "",
        "name": a.get("meaningful_name", "")[:60],
    }


def urlscan_lookup(domain: str, key: str) -> dict:
    resp = requests.get(URLSCAN_URL, params={"q": f"domain:{domain}", "size": 5}, headers={"API-Key": key}, timeout=TIMEOUT)
    if resp.status_code == 429:
        raise RuntimeError("urlscan.io: gränsen nådd (429)")
    resp.raise_for_status()
    data = resp.json()
    res = data.get("results", [])
    latest = max((r.get("task", {}).get("time", "") for r in res), default="")
    return {"total": int(data.get("total", len(res))), "last": latest[:10],
            "ip": (res[0].get("page", {}).get("ip", "") if res else ""), "country": (res[0].get("page", {}).get("country", "") if res else "")}


def _candidates(conn, ioc_type, limit):
    cached = {r[0] for r in conn.execute("SELECT value FROM lookup_cache WHERE kind = ?", ("vt" if ioc_type == "sha256_hash" else "urlscan",))}
    try:
        rows = conn.execute(
            "SELECT value FROM ioc_scores WHERE ioc_type = ? AND score >= 70 AND status != 'inaktuell' ORDER BY score DESC, last_seen DESC LIMIT 200",
            (ioc_type,)).fetchall()
    except sqlite3.Error:
        return []
    return [r[0] for r in rows if r[0] not in cached][:limit]


def run_lookups(db_path: str = DB_PATH, vt=vt_lookup, us=urlscan_lookup, sleep=time.sleep) -> int:
    vt_key, us_key = os.environ.get("VT_API_KEY", ""), os.environ.get("URLSCAN_API_KEY", "")
    if not (vt_key or us_key):
        print("[+] Uppslag: VT_API_KEY/URLSCAN_API_KEY saknas, funktionen är avstängd.")
        return 0
    conn = _connect(db_path)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    done = 0
    try:
        if vt_key:
            for h in _candidates(conn, "sha256_hash", VT_PER_RUN):
                conn.execute("INSERT OR REPLACE INTO lookup_cache VALUES ('vt', ?, ?, ?)", (h, json.dumps(vt(h, vt_key)), now))
                conn.commit()
                done += 1
                sleep(VT_PAUSE)
        if us_key:
            for d in _candidates(conn, "domain", URLSCAN_PER_RUN):
                conn.execute("INSERT OR REPLACE INTO lookup_cache VALUES ('urlscan', ?, ?, ?)", (d, json.dumps(us(d, us_key)), now))
                conn.commit()
                done += 1
                sleep(1)
    except RuntimeError as e:  # gränsen nådd: spara det som hunnit göras
        print(f"    Uppslag: {e}", file=sys.stderr)
    finally:
        conn.close()
    print(f"[+] Uppslag: {done} nya uppslag.")
    return done


LOOKUPS_CSS = """
  .lk-table { width: 100%; border-collapse: collapse; font-size: 0.83rem; }
  .lk-table th { text-align: left; font-weight: 500; color: var(--text-dim); font-size: 0.74rem; padding: 0.3rem 0.5rem; border-bottom: 1px solid var(--panel-border); }
  .lk-table td { padding: 0.3rem 0.5rem; border-bottom: 1px solid var(--panel-border); }
  .lk-table td.m { font-family: var(--mono, monospace); word-break: break-all; }
  .lk-bad { color: var(--red); font-weight: 600; }
"""


def build_lookups_html(db_path: str = DB_PATH) -> str:
    if not (os.environ.get("VT_API_KEY") or os.environ.get("URLSCAN_API_KEY")):
        try:
            conn = _connect(db_path)
            n = conn.execute("SELECT COUNT(*) FROM lookup_cache").fetchone()[0]
            conn.close()
        except sqlite3.Error:
            n = 0
        if not n:
            return ('<p class="empty">Avstängt: lägg secrets <code>VT_API_KEY</code> (VirusTotal) och/eller <code>URLSCAN_API_KEY</code> (urlscan.io) '
                    'för att slå på uppslag av nya hashar och domäner. Läs villkoren i lookups.py först.</p>')
    try:
        conn = _connect(db_path)
        rows = conn.execute("SELECT kind, value, result, checked_at FROM lookup_cache ORDER BY checked_at DESC LIMIT 40").fetchall()
        conn.close()
    except sqlite3.Error:
        rows = []
    if not rows:
        return '<p class="empty">Inga uppslag gjorda ännu, fylls vid nästa körning.</p>'
    body = []
    for kind, value, result, checked in rows:
        r = json.loads(result or "{}")
        if kind == "vt":
            if r.get("unknown"):
                txt = "okänd hos VirusTotal"
            else:
                bad = r.get("malicious", 0)
                txt = (f'<span class="{"lk-bad" if bad else ""}">{bad}/{r.get("total", 0)} motorer flaggar</span>'
                       f' · {html.escape(r.get("label", "") or "ingen etikett")} · först sedd {html.escape(r.get("first", "") or "?")}')
        else:
            txt = f'{r.get("total", 0)} publika skanningar' + (f' · senast {html.escape(r.get("last", ""))}' if r.get("last") else "") + \
                  (f' · {html.escape(r.get("ip", ""))} {html.escape(r.get("country", ""))}' if r.get("ip") else "")
        body.append(f'<tr><td>{"VirusTotal" if kind == "vt" else "urlscan.io"}</td><td class="m">{html.escape(value[:70])}</td><td>{txt}</td><td>{html.escape((checked or "")[:10])}</td></tr>')
    return ('<table class="lk-table"><tr><th>Källa</th><th>Värde</th><th>Resultat</th><th>Uppslag</th></tr>' + "".join(body) + "</table>"
            '<p class="dim" style="font-size:0.78rem;white-space:normal">Bara hashar och domäner med hög poäng slås upp, en gång var och max några per körning. '
            'Endast en sammanfattning sparas.</p>')


if __name__ == "__main__":
    run_lookups()
