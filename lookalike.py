"""
Look-alike-domäner — hittar registrerade domäner som liknar dina (config_org.py), ofta använda för phishing.

Så funkar det:
  1. Genererar stavningsvarianter av varje bevakad domän: utelämnade, dubblerade och bytta tecken,
     grannknappar på tangentbordet, liknande tecken (rn/m, l/1, o/0 m.fl.), bindestreck, andra
     toppdomäner och ord som login/secure/portal.
  2. Varianterna sparas i tabellen lookalike_domains. Per körning kontrolleras de som väntat längst
     (LOOKALIKES_PER_RUN st) via DNS-over-HTTPS (Cloudflare): finns den (A-post), har den mejlserver (MX)?
  3. För domäner som finns hämtas registreringsdatum via RDAP (rdap.org) och om certifikat utfärdats (crt.sh).
  4. Poäng 0-100: nyregistrerad (<30 dagar +40, <90 dagar +20), har MX +25, finns i DNS +15, har
     certifikat +20, och typ av variant (tecken som liknar mest) upp till +10.
Domäner du markerat som ofarliga i config_org.py (safe_domains) hoppas över.
Inga anrop går till de misstänkta webbplatserna själva, bara till DNS, RDAP och certifikatloggar.
"""

import html
import json
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import requests

from config_org import LOOKALIKES_PER_RUN, ORG
from storage import DB_PATH

DOH = "https://cloudflare-dns.com/dns-query"
RDAP = "https://rdap.org/domain/{d}"
CRTSH = "https://crt.sh/?q={d}&output=json"
TIMEOUT = 15
UA = {"User-Agent": "Mozilla/5.0 (compatible; cti-agent)"}

TLDS = ["com", "net", "org", "se", "nu", "info", "online", "co", "io", "eu", "xyz", "top", "site", "app"]
KEYWORDS = ["login", "secure", "portal", "support", "mitt", "konto", "service", "online"]
KEYBOARD = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok", "o": "ipl", "p": "o",
    "a": "qsz", "s": "awdx", "d": "serfc", "f": "drtgv", "g": "ftyhb", "h": "gyujn", "j": "huikm", "k": "jiolm", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}
HOMOGLYPHS = [("rn", "m"), ("m", "rn"), ("l", "1"), ("i", "1"), ("o", "0"), ("l", "i"), ("i", "l"), ("w", "vv"), ("cl", "d"), ("d", "cl")]
KIND_WEIGHT = {"homoglyph": 10, "omission": 8, "transposition": 8, "replacement": 6, "repetition": 6, "insertion": 5,
               "hyphen": 6, "tld": 4, "keyword": 7}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS lookalike_domains (
    domain TEXT PRIMARY KEY,
    base TEXT, kind TEXT,
    resolved INTEGER, has_mx INTEGER, created TEXT, registrar TEXT, has_cert INTEGER,
    score INTEGER DEFAULT 0, first_seen TEXT, checked_at TEXT
)
"""


def _connect(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute(_SCHEMA)
    return conn


def split_domain(domain: str):
    label, _, tld = domain.lower().strip(".").partition(".")
    return label, tld


def generate_variants(domain: str) -> dict:
    """{variant-domän: sort} för en bevakad domän. Själva domänen ingår aldrig."""
    label, tld = split_domain(domain)
    out = {}

    def add(l, t, kind):
        l = l.strip("-")
        if l and 3 <= len(l) <= 63 and (l != label or t != tld):
            out.setdefault(f"{l}.{t}", kind)

    for i in range(len(label)):
        add(label[:i] + label[i + 1:], tld, "omission")
        add(label[:i] + label[i] * 2 + label[i + 1:], tld, "repetition")
        for ch in KEYBOARD.get(label[i], ""):
            add(label[:i] + ch + label[i + 1:], tld, "replacement")
    for i in range(len(label) - 1):
        if label[i] != label[i + 1]:
            add(label[:i] + label[i + 1] + label[i] + label[i + 2:], tld, "transposition")
    for a, b in HOMOGLYPHS:
        start = 0
        while True:
            i = label.find(a, start)
            if i < 0:
                break
            add(label[:i] + b + label[i + len(a):], tld, "homoglyph")
            start = i + 1
    for i in range(1, len(label)):
        add(label[:i] + "-" + label[i:], tld, "hyphen")
    for t in TLDS:
        if t != tld:
            add(label, t, "tld")
    for k in KEYWORDS:
        for t in {tld, "com"}:
            add(f"{label}-{k}", t, "keyword")
            add(f"{k}-{label}", t, "keyword")
            add(f"{label}{k}", t, "keyword")
    return out


def score_lookalike(kind, resolved, has_mx, created, has_cert, today=None) -> int:
    today = today or datetime.now(timezone.utc).date()
    if not resolved and not has_mx:
        return 0
    s = KIND_WEIGHT.get(kind, 4) + (15 if resolved else 0) + (25 if has_mx else 0) + (20 if has_cert else 0)
    if created:
        try:
            age = (today - datetime.strptime(created[:10], "%Y-%m-%d").date()).days
            s += 40 if age < 30 else 20 if age < 90 else 0
        except ValueError:
            pass
    return min(100, s)


# ------------------------------------------------------------------ uppslag
def doh(name: str, rtype: str) -> list:
    resp = requests.get(DOH, params={"name": name, "type": rtype}, timeout=TIMEOUT,
                        headers={"accept": "application/dns-json", **UA})
    resp.raise_for_status()
    return [a for a in resp.json().get("Answer", []) if a.get("type") in (1, 28, 15)]


def rdap_created(domain: str):
    resp = requests.get(RDAP.format(d=domain), timeout=TIMEOUT, headers=UA)
    if resp.status_code != 200:
        return "", ""
    data = resp.json()
    created = next((e.get("eventDate", "")[:10] for e in data.get("events", []) if e.get("eventAction") == "registration"), "")
    registrar = ""
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            v = ent.get("vcardArray", [None, []])[1]
            registrar = next((x[3] for x in v if x and x[0] == "fn"), "")
    return created, registrar


def has_certificate(domain: str) -> bool:
    resp = requests.get(CRTSH.format(d=domain), timeout=45, headers=UA)
    return resp.status_code == 200 and bool(resp.json())


def check_domain(domain: str, kind: str, doh_fn=doh, rdap_fn=rdap_created, cert_fn=has_certificate) -> dict:
    res = {"domain": domain, "resolved": 0, "mx": 0, "created": "", "registrar": "", "cert": 0}
    try:
        res["resolved"] = int(bool([a for a in doh_fn(domain, "A") if a.get("type") == 1] or doh_fn(domain, "AAAA")))
        res["mx"] = int(bool(doh_fn(domain, "MX")))
    except Exception:
        res["error"] = True
        return res
    if res["resolved"] or res["mx"]:
        try:
            res["created"], res["registrar"] = rdap_fn(domain)
        except Exception:
            pass
        try:
            res["cert"] = int(cert_fn(domain))
        except Exception:
            pass
    return res


def run_lookalikes(db_path: str = DB_PATH, limit: int = LOOKALIKES_PER_RUN, domains=None, check=check_domain) -> int:
    domains = domains if domains is not None else ORG["domains"]
    if not domains:
        print("[+] Look-alike: inga domäner i config_org.py, hoppar över.")
        return 0
    safe = {d.lower() for d in ORG["safe_domains"]} | {d.lower() for d in domains}
    conn = _connect(db_path)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    for base in domains:
        for v, kind in generate_variants(base).items():
            if v not in safe:
                conn.execute("INSERT OR IGNORE INTO lookalike_domains (domain, base, kind, first_seen) VALUES (?, ?, ?, ?)", (v, base, kind, now))
    conn.commit()
    todo = conn.execute(
        "SELECT domain, kind FROM lookalike_domains ORDER BY (checked_at IS NOT NULL), checked_at LIMIT ?", (limit,)).fetchall()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda t: (t, check(t[0], t[1])), todo))
    found = errors = 0
    for (dom, kind), r in results:
        if r.get("error"):
            errors += 1
            continue
        s = score_lookalike(kind, r["resolved"], r["mx"], r["created"], r["cert"])
        conn.execute(
            "UPDATE lookalike_domains SET resolved=?, has_mx=?, created=?, registrar=?, has_cert=?, score=?, checked_at=? WHERE domain=?",
            (r["resolved"], r["mx"], r["created"], r["registrar"], r["cert"], s, now, dom))
        found += 1 if r["resolved"] or r["mx"] else 0
    conn.commit()
    conn.close()
    print(f"[+] Look-alike: {len(todo)} varianter kontrollerade, {found} finns i DNS, {errors} fel.", file=sys.stdout)
    if todo and errors == len(todo):
        raise RuntimeError("alla DNS-uppslag misslyckades (DoH nåbar?)")
    return found


# ------------------------------------------------------------------ larm och visning
def lookalike_alerts(db_path: str = DB_PATH) -> list:
    try:
        conn = _connect(db_path)
        rows = conn.execute(
            "SELECT domain, base, score, created, has_mx, has_cert FROM lookalike_domains WHERE score >= 60 ORDER BY score DESC LIMIT 30").fetchall()
        conn.close()
    except sqlite3.Error:
        return []
    out = []
    for d, base, s, created, mx, cert in rows:
        extra = ", ".join(x for x in (f"registrerad {created}" if created else "", "har mejlserver" if mx else "", "har certifikat" if cert else "") if x)
        out.append({"kind": "lookalike", "level": "Hög" if s >= 80 else "Medel", "key": f"lookalike:{d}",
                    "title": f"Look-alike av {base}: {d} (poäng {s})", "detail": extra or "Finns i DNS."})
    return out


LOOKALIKE_CSS = """
  .la-table { width: 100%; border-collapse: collapse; font-size: 0.83rem; }
  .la-table th { text-align: left; font-weight: 500; color: var(--text-dim); font-size: 0.74rem; padding: 0.3rem 0.5rem; border-bottom: 1px solid var(--panel-border); }
  .la-table td { padding: 0.3rem 0.5rem; border-bottom: 1px solid var(--panel-border); }
  .la-table td.m { font-family: var(--mono, monospace); }
"""


def build_lookalike_html(db_path: str = DB_PATH) -> str:
    if not ORG["domains"]:
        return '<p class="empty">Inga domäner i config_org.py.</p>'
    try:
        conn = _connect(db_path)
        total = conn.execute("SELECT COUNT(*) FROM lookalike_domains").fetchone()[0]
        checked = conn.execute("SELECT COUNT(*) FROM lookalike_domains WHERE checked_at IS NOT NULL").fetchone()[0]
        rows = conn.execute(
            "SELECT domain, base, kind, score, created, registrar, has_mx, has_cert FROM lookalike_domains "
            "WHERE (resolved = 1 OR has_mx = 1) ORDER BY score DESC, created DESC LIMIT 40").fetchall()
        conn.close()
    except sqlite3.Error:
        return '<p class="empty">Look-alike-kontrollen har inte körts ännu.</p>'
    if not total:
        return '<p class="empty">Look-alike-kontrollen har inte körts ännu, fylls efter nästa körning.</p>'
    kinds = {"omission": "utelämnat tecken", "repetition": "dubblat tecken", "replacement": "grannknapp", "transposition": "bytt plats",
             "homoglyph": "liknande tecken", "hyphen": "bindestreck", "tld": "annan toppdomän", "keyword": "extra ord"}
    body = "".join(
        f'<tr><td class="m">{html.escape(d)}</td><td>{html.escape(kinds.get(k, k))}</td><td><b>{s}</b></td>'
        f'<td>{html.escape(c or "okänt")}</td><td>{html.escape(r or "")}</td><td>{"ja" if mx else "nej"}</td><td>{"ja" if cert else "nej"}</td></tr>'
        for d, _b, k, s, c, r, mx, cert in rows) or '<tr><td colspan="7" class="dim">Inga registrerade look-alikes hittade hittills.</td></tr>'
    return (
        f'<p class="dim" style="font-size:0.8rem;white-space:normal">{checked} av {total} varianter av '
        f'{html.escape(", ".join(ORG["domains"]))} kontrollerade ({LOOKALIKES_PER_RUN} per körning). Visar de som finns i DNS, högst poäng först.</p>'
        '<table class="la-table"><tr><th>Domän</th><th>Variant</th><th>Poäng</th><th>Registrerad</th><th>Registrar</th><th>Mejlserver</th><th>Certifikat</th></tr>'
        + body + "</table>"
        '<p class="dim" style="font-size:0.78rem;white-space:normal">Poäng: nyregistrerad, mejlserver, certifikat och typ av variant. Domäner du har kontrollerat '
        'och vet är legitima läggs i <code>safe_domains</code> i config_org.py.</p>')


if __name__ == "__main__":
    run_lookalikes()
