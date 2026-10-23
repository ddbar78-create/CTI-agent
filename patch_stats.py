"""
Patchstatistik — hur många sårbarheter som lagas per månad i Windows- och Linux-världen.

Källor (alla öppna, inga nycklar):
  Microsoft   MSRC CVRF (månadsvisa Patch Tuesday-dokument, XML):
              totalt, kritiska, exploaterade, publikt kända, vanligaste typer
  Red Hat     Security Data API: CVE:er per månad och allvarlighetsgrad
  Ubuntu      Security notices API: säkerhetsmeddelanden (USN), åtgärdade CVE:er, kärnmeddelanden
  CISA KEV    aktivt utnyttjade sårbarheter per leverantör (Microsoft, Linux m.fl.), 12 månader

Hämtas högst var 12:e timme (resultatet sparas i tabellen patch_stats). Varje källa
körs för sig och registrerar sin status, så att ett fel i en inte stoppar de andra.

Tolkning: antalen visar patchvolym, inte risk. Microsofts siffror inkluderar även
Edge/Chromium och tredjepartskomponenter i Update Guide. Red Hat räknar CVE:er de
har gjort en bedömning av, inte alla Linux-sårbarheter.
"""

import html
import sqlite3
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import requests

from storage import DB_PATH
from run_status import record

TIMEOUT = 40
MONTHS_BACK = 6
KEV_MONTHS_BACK = 12
REFRESH_HOURS = 12
UA = {"User-Agent": "cti-agent (patch statistics)"}
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
UBUNTU_URL = "https://ubuntu.com/security/notices.json"
REDHAT_URL = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
MSRC_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{id}"
EN_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
SV_MONTHS = ["jan", "feb", "mar", "apr", "maj", "jun", "jul", "aug", "sep", "okt", "nov", "dec"]
SEVERITY_ORDER = {"critical": 4, "important": 3, "moderate": 2, "low": 1}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS patch_stats (
    vendor TEXT NOT NULL,
    period TEXT NOT NULL,
    metric TEXT NOT NULL,
    value INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (vendor, period, metric)
)
"""


# ---------------------------------------------------------------- hjälpfunktioner
def _months(n: int, today=None) -> list:
    """Senaste n månaderna, äldst först, som (år, månad)."""
    today = today or datetime.now(timezone.utc)
    y, m = today.year, today.month
    out = []
    for _ in range(n):
        out.append((y, m))
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    return list(reversed(out))


def _key(y: int, m: int) -> str:
    return f"{y:04d}-{m:02d}"


def _next_month(y: int, m: int) -> tuple:
    return (y + 1, 1) if m == 12 else (y, m + 1)


def _connect(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute(_SCHEMA)
    return conn


def _store(conn, rows: list):
    """rows: [(vendor, period, metric, value)] — ersätter tidigare värden."""
    conn.executemany(
        """
        INSERT INTO patch_stats (vendor, period, metric, value) VALUES (?, ?, ?, ?)
        ON CONFLICT(vendor, period, metric) DO UPDATE SET value = excluded.value
        """,
        rows,
    )


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


# ---------------------------------------------------------------- Microsoft
def parse_msrc_xml(content: bytes) -> dict:
    """Tolkar ett MSRC CVRF-dokument till räknare. Varje CVE räknas en gång."""
    root = ET.fromstring(content)
    total = critical = exploited = disclosed = 0
    impacts: dict = {}
    seen = set()
    for vuln in root.iter():
        if _local(vuln.tag) != "Vulnerability":
            continue
        cve = ""
        severity = ""
        impact_set = set()
        is_exploited = is_disclosed = False
        for el in vuln.iter():
            name = _local(el.tag)
            if name == "CVE" and el.text:
                cve = el.text.strip()
            elif name == "Threat":
                ttype = (el.attrib.get("Type") or "").strip().lower()
                desc = ""
                for ch in el:
                    if _local(ch.tag) == "Description" and ch.text:
                        desc = ch.text.strip()
                if not desc:
                    continue
                if "exploited:yes" in desc.replace(" ", "").lower():
                    is_exploited = True
                if "publiclydisclosed:yes" in desc.replace(" ", "").lower():
                    is_disclosed = True
                if ttype == "severity":
                    if SEVERITY_ORDER.get(desc.lower(), 0) > SEVERITY_ORDER.get(severity, 0):
                        severity = desc.lower()
                elif ttype == "impact":
                    impact_set.add(desc)
        if not cve or cve in seen:
            continue
        seen.add(cve)
        total += 1
        critical += severity == "critical"
        exploited += is_exploited
        disclosed += is_disclosed
        for i in impact_set:
            impacts[i] = impacts.get(i, 0) + 1
    return {"total": total, "critical": critical, "exploited": exploited,
            "disclosed": disclosed, "impacts": impacts}


def fetch_microsoft() -> list:
    rows, got = [], 0
    for y, m in _months(MONTHS_BACK):
        doc_id = f"{y}-{EN_MONTHS[m - 1]}"
        resp = requests.get(MSRC_URL.format(id=doc_id), timeout=TIMEOUT,
                            headers={**UA, "Accept": "application/xml"})
        if resp.status_code == 404:  # månadens dokument finns inte (ännu)
            continue
        resp.raise_for_status()
        stats = parse_msrc_xml(resp.content)
        if not stats["total"]:
            continue
        got += 1
        p = _key(y, m)
        rows += [("Microsoft", p, "total", stats["total"]), ("Microsoft", p, "critical", stats["critical"]),
                 ("Microsoft", p, "exploited", stats["exploited"]), ("Microsoft", p, "disclosed", stats["disclosed"])]
        rows += [("Microsoft", p, f"impact:{k}", v) for k, v in stats["impacts"].items()]
        time.sleep(0.5)
    if not got:
        raise RuntimeError("inga Microsoft-dokument kunde läsas")
    return rows


# ---------------------------------------------------------------- Red Hat
def fetch_redhat() -> list:
    rows = []
    for y, m in _months(MONTHS_BACK):
        ny, nm = _next_month(y, m)
        counts = {"critical": 0, "important": 0, "moderate": 0, "low": 0, "other": 0}
        total, page = 0, 1
        while page <= 15:
            resp = requests.get(
                REDHAT_URL, timeout=TIMEOUT, headers=UA,
                params={"after": f"{y:04d}-{m:02d}-01", "before": f"{ny:04d}-{nm:02d}-01",
                        "per_page": 1000, "page": page},
            )
            resp.raise_for_status()
            data = resp.json()
            if not data:
                break
            for c in data:
                sev = (c.get("severity") or "").lower()
                counts[sev if sev in counts else "other"] += 1
                total += 1
            if len(data) < 1000:
                break
            page += 1
            time.sleep(0.3)
        p = _key(y, m)
        rows.append(("Red Hat", p, "total", total))
        rows += [("Red Hat", p, k, v) for k, v in counts.items()]
        time.sleep(0.3)
    return rows


# ---------------------------------------------------------------- Ubuntu
def fetch_ubuntu() -> list:
    months = _months(MONTHS_BACK)
    start = _key(*months[0])
    notices: dict = {}
    cves: dict = {}
    kernel: dict = {}
    offset, limit, use_order = 0, 50, True
    for _ in range(200):
        params = {"limit": limit, "offset": offset}
        if use_order:
            params["order"] = "newest"
        resp = requests.get(UBUNTU_URL, timeout=TIMEOUT, headers=UA, params=params)
        if resp.status_code in (400, 422):
            # API:et kan avvisa limit, order eller för stor offset: prova enklare parametrar,
            # och använd det som redan hämtats om det går fel längre in.
            if use_order:
                use_order = False
                continue
            if limit != 20:
                limit = 20
                continue
            if offset > 0:
                break
        resp.raise_for_status()
        batch = resp.json().get("notices", [])
        if not batch:
            break
        oldest_in_range = False
        for n in batch:
            p = (n.get("published") or "")[:7]
            if not p or p < start:
                continue
            oldest_in_range = True
            notices[p] = notices.get(p, 0) + 1
            cves.setdefault(p, set()).update(n.get("cves_ids") or [c.get("id") for c in n.get("cves", []) if c.get("id")])
            if "kernel" in (n.get("title") or "").lower():
                kernel[p] = kernel.get(p, 0) + 1
        if not oldest_in_range:
            break
        offset += len(batch)
        time.sleep(0.3)
    rows = []
    for y, m in months:
        p = _key(y, m)
        rows += [("Ubuntu", p, "notices", notices.get(p, 0)), ("Ubuntu", p, "cves", len(cves.get(p, ()))),
                 ("Ubuntu", p, "kernel", kernel.get(p, 0))]
    return rows


# ---------------------------------------------------------------- CISA KEV
def fetch_kev() -> list:
    resp = requests.get(KEV_URL, timeout=TIMEOUT, headers=UA)
    resp.raise_for_status()
    wanted = {_key(y, m) for y, m in _months(KEV_MONTHS_BACK)}
    added: dict = {}
    ransom: dict = {}
    for v in resp.json().get("vulnerabilities", []):
        p = (v.get("dateAdded") or "")[:7]
        if p not in wanted:
            continue
        vendor = (v.get("vendorProject") or "okänd").strip()
        added[(vendor, p)] = added.get((vendor, p), 0) + 1
        if (v.get("knownRansomwareCampaignUse") or "").lower() == "known":
            ransom[(vendor, p)] = ransom.get((vendor, p), 0) + 1
    rows = [(f"KEV:{vendor}", p, "added", n) for (vendor, p), n in added.items()]
    rows += [(f"KEV:{vendor}", p, "ransomware", n) for (vendor, p), n in ransom.items()]
    return rows


# ---------------------------------------------------------------- körning
def run_patch_stats(db_path: str = DB_PATH, force: bool = False) -> int:
    conn = _connect(db_path)
    last = conn.execute("SELECT value FROM patch_stats WHERE vendor='_meta' AND period='last_run' AND metric='epoch'").fetchone()
    conn.close()
    if last and not force and time.time() - last[0] < REFRESH_HOURS * 3600:
        print("[+] Patchstatistik: uppdaterad nyligen, hoppar över.")
        return 0

    print("[+] Patchstatistik: hämtar Microsoft, Red Hat, Ubuntu och KEV ...")
    total_rows = 0
    results = []  # (källa, rader, fel)
    for label, fn in (("Patch: Microsoft", fetch_microsoft), ("Patch: Red Hat", fetch_redhat),
                      ("Patch: Ubuntu", fetch_ubuntu), ("Patch: CISA KEV", fetch_kev)):
        try:
            rows = fn()
            results.append((label, rows, ""))
        except Exception as e:
            print(f"    {label}: FEL – {e}", file=sys.stderr)
            results.append((label, [], str(e)))

    conn = _connect(db_path)
    for label, rows, err in results:
        if rows:
            _store(conn, rows)
            total_rows += len(rows)
    ok_any = any(rows for _l, rows, _e in results)
    if ok_any:
        _store(conn, [("_meta", "last_run", "epoch", int(time.time()))])
    conn.commit()
    conn.close()

    for label, rows, err in results:  # efter att anslutningen stängts
        record(label, 0 if err else 1, len(rows), err)
    print(f"    Patchstatistik: {total_rows} värden sparade.")
    return total_rows


# ---------------------------------------------------------------- visning
PATCH_CSS = """
  .ps-note { font-size: 0.78rem; margin-bottom: 0.8rem; white-space: normal; }
  .ps-h { font-size: 0.78rem; margin: 1.1rem 0 0.4rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.04em; }
  .ps-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  .ps-table th { text-align: left; font-weight: 500; color: var(--text-dim); font-size: 0.75rem; padding: 0.3rem 0.5rem; border-bottom: 1px solid var(--panel-border); }
  .ps-table td { padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--panel-border); vertical-align: middle; }
  .ps-table td.num { font-family: var(--mono, monospace); text-align: right; white-space: nowrap; }
  .ps-bar { display: inline-block; height: 0.55rem; background: var(--accent, #6ea8fe); border-radius: 2px; vertical-align: middle; margin-right: 0.4rem; opacity: 0.8; }
  .ps-bar.red { background: var(--red); }
  .ps-up { color: var(--red); } .ps-down { color: var(--green, #3fb950); }
  .ps-kev { display: grid; grid-template-columns: minmax(8rem, 14rem) 1fr auto; gap: 0.5rem; align-items: center; font-size: 0.85rem; padding: 0.15rem 0; }
"""


def _esc(v) -> str:
    return html.escape(str(v)) if v is not None else ""


def _load(db_path: str) -> dict:
    conn = _connect(db_path)
    data: dict = {}
    for vendor, period, metric, value in conn.execute(
            "SELECT vendor, period, metric, value FROM patch_stats WHERE vendor != '_meta'"):
        data.setdefault(vendor, {}).setdefault(period, {})[metric] = value
    conn.close()
    return data


def _label(period: str) -> str:
    y, m = period.split("-")
    return f"{SV_MONTHS[int(m) - 1]} {y}"


def _delta(cur, prev) -> str:
    if not prev:
        return ""
    pct = round((cur - prev) / prev * 100)
    if pct == 0:
        return ""
    cls = "ps-up" if pct > 0 else "ps-down"
    return f' <span class="{cls}">{"↑" if pct > 0 else "↓"}{abs(pct)}%</span>'


def build_patch_stats_html(db_path: str = DB_PATH) -> str:
    data = _load(db_path)
    if not data:
        return '<p class="empty">Ingen patchstatistik ännu — fylls efter nästa körning (se källstatus överst).</p>'

    periods = [_key(y, m) for y, m in _months(MONTHS_BACK)]
    out = ['<p class="dim ps-note">Antal sårbarheter som åtgärdas per månad. Patchvolym är inte detsamma som risk: '
           'Microsofts siffror omfattar även Edge/Chromium och tredjepartskomponenter, Red Hat räknar CVE:er de bedömt, '
           'och Ubuntu räknar säkerhetsmeddelanden (USN). Pilen visar förändring mot föregående månad.</p>']

    ms = data.get("Microsoft", {})
    if ms:
        mx = max((ms.get(p, {}).get("total", 0) for p in periods), default=1) or 1
        rows = []
        prev = None
        for p in periods:
            d = ms.get(p)
            if not d:
                rows.append(f'<tr><td>{_label(p)}</td><td colspan="5" class="dim">ingen data</td></tr>')
                continue
            top = sorted(((k[7:], v) for k, v in d.items() if k.startswith("impact:")), key=lambda x: -x[1])[:3]
            top_s = ", ".join(f"{_esc(k)} ({v})" for k, v in top)
            w = max(2, round(d.get("total", 0) / mx * 120))
            rows.append(
                f'<tr><td>{_label(p)}</td>'
                f'<td class="num"><span class="ps-bar" style="width:{w}px"></span>{d.get("total", 0)}{_delta(d.get("total", 0), prev)}</td>'
                f'<td class="num">{d.get("critical", 0)}</td><td class="num">{d.get("exploited", 0)}</td>'
                f'<td class="num">{d.get("disclosed", 0)}</td><td class="dim">{top_s}</td></tr>')
            prev = d.get("total", 0)
        out.append('<div class="ps-h">Windows / Microsoft — Patch Tuesday</div><table class="ps-table"><tr>'
                   '<th>Månad</th><th>Totalt</th><th>Kritiska</th><th>Exploaterade</th><th>Publikt kända</th>'
                   '<th>Vanligaste typer</th></tr>' + "".join(rows) + "</table>")

    rh, ub = data.get("Red Hat", {}), data.get("Ubuntu", {})
    if rh or ub:
        mx = max((rh.get(p, {}).get("total", 0) for p in periods), default=1) or 1
        rows, prev = [], None
        for p in periods:
            r, u = rh.get(p, {}), ub.get(p, {})
            w = max(2, round(r.get("total", 0) / mx * 120)) if r else 0
            rows.append(
                f'<tr><td>{_label(p)}</td>'
                f'<td class="num"><span class="ps-bar" style="width:{w}px"></span>{r.get("total", "–")}{_delta(r.get("total", 0), prev) if r else ""}</td>'
                f'<td class="num">{r.get("critical", "–")}</td><td class="num">{r.get("important", "–")}</td>'
                f'<td class="num">{u.get("notices", "–")}</td><td class="num">{u.get("cves", "–")}</td>'
                f'<td class="num">{u.get("kernel", "–")}</td></tr>')
            prev = r.get("total") if r else prev
        out.append('<div class="ps-h">Linux — Red Hat och Ubuntu</div><table class="ps-table"><tr>'
                   '<th>Månad</th><th>Red Hat CVE:er</th><th>varav kritiska</th><th>varav viktiga</th>'
                   '<th>Ubuntu USN</th><th>Ubuntu CVE:er</th><th>varav kärna (USN)</th></tr>'
                   + "".join(rows) + "</table>")

    kev = {v[4:]: d for v, d in data.items() if v.startswith("KEV:")}
    if kev:
        totals = sorted(((v, sum(x.get("added", 0) for x in d.values())) for v, d in kev.items()), key=lambda x: -x[1])
        top = totals[:10]
        mx = top[0][1] if top else 1
        bars = "".join(
            f'<div class="ps-kev"><span>{_esc(v)}</span><span><span class="ps-bar red" style="width:{max(2, round(n / mx * 220))}px"></span></span>'
            f'<span class="mono">{n}</span></div>' for v, n in top)
        out.append('<div class="ps-h">Aktivt utnyttjade (CISA KEV) per leverantör, senaste 12 månaderna</div>' + bars)

        focus = [(v, kev[v]) for v in ("Microsoft", "Linux") if v in kev]
        if focus:
            kp = [_key(y, m) for y, m in _months(KEV_MONTHS_BACK)]
            head = "".join(f"<th>{_label(p)}</th>" for p in kp)
            body = "".join(
                f'<tr><td>{_esc(v)}</td>' + "".join(f'<td class="num">{d.get(p, {}).get("added", 0)}</td>' for p in kp) + "</tr>"
                for v, d in focus)
            out.append('<div class="ps-h">Nya KEV-poster per månad: Microsoft och Linux</div>'
                       f'<div style="overflow-x:auto"><table class="ps-table"><tr><th>Leverantör</th>{head}</tr>{body}</table></div>')

    return "".join(out)


if __name__ == "__main__":
    run_patch_stats(force=True)
