"""
Attackyta — bevakar din organisations offentliga yta (se config_org.py) och larmar om förändringar.

Inga egna skanningar. Modulen slår bara upp vad andra redan vet:
  - Shodan InternetDB (https://internetdb.shodan.io/<ip>, gratis, ingen nyckel): öppna portar,
    produkter (CPE), kända sårbarheter (CVE), värdnamn och taggar per IPv4-adress
  - certifikatloggar via crt.sh: underdomäner och när certifikaten går ut

Hela IP-intervallet roteras över flera körningar (SURFACE_IPS_PER_RUN per körning), de som kontrollerats
längst sedan först. Varje IP sparar en ögonblicksbild; skillnader mot förra bilden blir fynd:
  - ny öppen port                   (Hög, Kritisk för administrations- och databastjänster)
  - ny känd sårbarhet på en värd    (Hög, Kritisk om aktivt utnyttjad enligt CISA KEV)
  - ny underdomän i certifikatloggen (Medel)
  - certifikat som går ut inom 30 dagar (Medel)
Första gången en IP ses räknas som utgångsläge (inga "nya port"-fynd), men redan exponerade
riskportar och sårbarheter flaggas en gång.

Tabeller: surface_hosts, surface_findings, surface_domains.
"""

import html
import ipaddress
import json
import socket
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone

import requests

from config_org import ORG, SURFACE_IPS_PER_RUN
from storage import DB_PATH

INTERNETDB = "https://internetdb.shodan.io/{ip}"
CRTSH = "https://crt.sh/?q=%25.{domain}&output=json"
TIMEOUT = 30
UA = {"User-Agent": "Mozilla/5.0 (compatible; cti-agent)"}

CRITICAL_PORTS = {
    21: "FTP", 23: "Telnet", 135: "RPC", 445: "SMB", 1433: "MS SQL", 1521: "Oracle", 2375: "Docker API",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch",
    27017: "MongoDB", 11211: "Memcached", 5985: "WinRM", 22: "SSH",
}
# SSH (22) räknas som Hög, resten av listan som Kritisk
HIGH_ONLY = {22}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS surface_hosts (
    ip TEXT PRIMARY KEY,
    ports TEXT, vulns TEXT, hostnames TEXT, tags TEXT, cpes TEXT,
    first_seen TEXT, checked_at TEXT
);
CREATE TABLE IF NOT EXISTS surface_findings (
    key TEXT PRIMARY KEY,
    kind TEXT, level TEXT, title TEXT, detail TEXT, ip TEXT,
    first_seen TEXT, status TEXT DEFAULT 'öppen'
);
CREATE TABLE IF NOT EXISTS surface_domains (
    name TEXT PRIMARY KEY,
    first_seen TEXT, last_seen TEXT, not_after TEXT, issuer TEXT, resolved_ip TEXT
);
"""


def _connect(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.executescript(_SCHEMA)
    return conn


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def all_ips(ranges=None) -> list:
    out = []
    for r in ranges if ranges is not None else ORG["ip_ranges"]:
        try:
            net = ipaddress.ip_network(r, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            out.extend(str(h) for h in net.hosts())
    return out


def _is_kev(conn, cve: str) -> bool:
    try:
        row = conn.execute("SELECT kev FROM cve_enrichment WHERE cve_id = ?", (cve,)).fetchone()
        if row and row[0]:
            return True
        row = conn.execute(
            "SELECT 1 FROM articles WHERE feed = 'CISA KEV' AND title LIKE ? LIMIT 1", (f"%{cve}%",)).fetchone()
        return bool(row)
    except sqlite3.Error:
        return False


def _finding(conn, key, kind, level, title, detail, ip):
    cur = conn.execute(
        "INSERT OR IGNORE INTO surface_findings (key, kind, level, title, detail, ip, first_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (key, kind, level, title, detail, ip, _now()))
    if cur.rowcount == 0:  # fanns redan: öppna igen om det tidigare lösts (t.ex. porten öppnades på nytt)
        cur = conn.execute("UPDATE surface_findings SET status = 'öppen', first_seen = ? WHERE key = ? AND status = 'löst'", (_now(), key))
    return cur.rowcount


def fetch_internetdb(ip: str):
    """Returnerar dict eller None om Shodan inte har något om IP-adressen (404)."""
    resp = requests.get(INTERNETDB.format(ip=ip), timeout=TIMEOUT, headers=UA)
    if resp.status_code == 404:
        return None
    if resp.status_code == 429:
        raise RuntimeError("Shodan InternetDB: för många anrop (429)")
    resp.raise_for_status()
    return resp.json()


def diff_host(conn, ip, new, old):
    """Skapar fynd från skillnaden mellan ny och gammal bild. old=None betyder första gången."""
    ports = set(new.get("ports") or [])
    vulns = set(new.get("vulns") or [])
    count = 0
    first = old is None
    old_ports = set(json.loads(old["ports"])) if old else set()
    old_vulns = set(json.loads(old["vulns"])) if old else set()
    for p in sorted(ports):
        if p in CRITICAL_PORTS:
            name = CRITICAL_PORTS[p]
            lvl = "Hög" if p in HIGH_ONLY else "Kritisk"
            if p not in old_ports:
                count += _finding(conn, f"port:{ip}:{p}", "port", lvl,
                                  f"{'Exponerad' if first else 'Ny öppen'} {name}-tjänst på {ip}:{p}",
                                  f"{name} är nåbar från internet. {'Upptäckt vid första kontrollen.' if first else 'Fanns inte vid förra kontrollen.'}", ip)
        elif p not in old_ports and not first:
            count += _finding(conn, f"port:{ip}:{p}", "port", "Hög", f"Ny öppen port {ip}:{p}",
                              "Fanns inte vid förra kontrollen. Kontrollera om tjänsten ska vara exponerad.", ip)
    for c in sorted(vulns - old_vulns):
        kev = _is_kev(conn, c)
        count += _finding(conn, f"vuln:{ip}:{c}", "vuln", "Kritisk" if kev else "Hög",
                          f"{c} på {ip}" + (" (aktivt utnyttjad, CISA KEV)" if kev else ""),
                          "Shodan listar sårbarheten för tjänsten på adressen (kan vara falsklarm, verifiera version).", ip)
    # stängda portar: markera tidigare fynd som lösta
    for p in old_ports - ports:
        conn.execute("UPDATE surface_findings SET status = 'löst' WHERE key = ?", (f"port:{ip}:{p}",))
    for c in old_vulns - vulns:
        conn.execute("UPDATE surface_findings SET status = 'löst' WHERE key = ?", (f"vuln:{ip}:{c}",))
    return count


def run_host_scan(db_path: str = DB_PATH, limit: int = SURFACE_IPS_PER_RUN, ips=None, fetch=fetch_internetdb) -> int:
    ips = ips if ips is not None else all_ips()
    if not ips:
        print("[+] Attackyta: inga IP-intervall i config_org.py, hoppar över IP-delen.")
        return 0
    conn = _connect(db_path)
    checked = dict(conn.execute("SELECT ip, checked_at FROM surface_hosts"))
    todo = sorted(ips, key=lambda i: checked.get(i, ""))[:limit]
    findings = hosts = 0
    errors = 0
    for ip in todo:
        try:
            data = fetch(ip)
        except Exception as e:
            errors += 1
            print(f"    Attackyta: {ip}: {type(e).__name__}: {str(e)[:80]}", file=sys.stderr)
            if errors >= 5:
                print("    Attackyta: avbryter IP-delen efter upprepade fel.", file=sys.stderr)
                break
            continue
        row = conn.execute("SELECT ports, vulns FROM surface_hosts WHERE ip = ?", (ip,)).fetchone()
        old = {"ports": row[0], "vulns": row[1]} if row else None
        new = data or {"ports": [], "vulns": [], "hostnames": [], "tags": [], "cpes": []}
        findings += diff_host(conn, ip, new, old)
        conn.execute(
            """INSERT INTO surface_hosts (ip, ports, vulns, hostnames, tags, cpes, first_seen, checked_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(ip) DO UPDATE SET ports=excluded.ports, vulns=excluded.vulns, hostnames=excluded.hostnames,
                   tags=excluded.tags, cpes=excluded.cpes, checked_at=excluded.checked_at""",
            (ip, json.dumps(sorted(new.get("ports") or [])), json.dumps(sorted(new.get("vulns") or [])),
             json.dumps(new.get("hostnames") or []), json.dumps(new.get("tags") or []), json.dumps(new.get("cpes") or []),
             _now(), _now()))
        hosts += 1
        time.sleep(0.15)
    conn.commit()
    conn.close()
    print(f"[+] Attackyta: {hosts} IP-adresser kontrollerade, {findings} nya fynd.")
    return findings


# ------------------------------------------------------------------ underdomäner och certifikat
def parse_crtsh(entries: list) -> dict:
    """{namn: (not_after, utfärdare)} från crt.sh JSON. Jokertecken och e-postadresser hoppas över."""
    names = {}
    for e in entries:
        for n in str(e.get("name_value", "")).splitlines():
            n = n.strip().lower().lstrip("*.")
            if not n or "@" in n or " " in n:
                continue
            na = (e.get("not_after") or "")[:10]
            if n not in names or na > names[n][0]:
                names[n] = (na, e.get("issuer_name", ""))
    return names


def run_domain_scan(db_path: str = DB_PATH, domains=None, fetch=None) -> int:
    domains = domains if domains is not None else ORG["domains"]
    if not domains:
        return 0
    conn = _connect(db_path)
    today = datetime.now(timezone.utc).date()
    findings = 0
    known_before = {r[0] for r in conn.execute("SELECT name FROM surface_domains")}
    for dom in domains:
        try:
            if fetch:
                entries = fetch(dom)
            else:
                resp = requests.get(CRTSH.format(domain=dom), timeout=60, headers=UA)
                resp.raise_for_status()
                entries = resp.json()
        except Exception as e:
            print(f"    Attackyta: crt.sh för {dom}: {type(e).__name__}: {str(e)[:80]} (ofarligt, försöker igen nästa körning)", file=sys.stderr)
            continue
        names = parse_crtsh(entries)
        for name, (not_after, issuer) in names.items():
            if not (name == dom or name.endswith("." + dom)):
                continue
            ip = ""
            if name not in known_before:
                try:
                    ip = socket.gethostbyname(name)
                except OSError:
                    ip = ""
            conn.execute(
                """INSERT INTO surface_domains (name, first_seen, last_seen, not_after, issuer, resolved_ip)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET last_seen=excluded.last_seen, not_after=excluded.not_after,
                       issuer=excluded.issuer, resolved_ip=CASE WHEN excluded.resolved_ip != '' THEN excluded.resolved_ip ELSE resolved_ip END""",
                (name, _now(), _now(), not_after, issuer[:80], ip))
            if known_before and name not in known_before:  # inte första körningen: nya namn är fynd
                findings += _finding(conn, f"newsub:{name}", "subdomain", "Medel", f"Ny underdomän i certifikatloggen: {name}",
                                     f"Första gången ett certifikat syns för {name}. Kontrollera att den är avsiktlig.", ip)
            try:
                days_left = (datetime.strptime(not_after, "%Y-%m-%d").date() - today).days if not_after else None
            except ValueError:
                days_left = None
            if days_left is not None and 0 <= days_left <= 30:
                findings += _finding(conn, f"cert:{name}:{not_after}", "cert", "Medel", f"Certifikat för {name} går ut om {days_left} dagar",
                                     f"Giltigt till {not_after}. Gäller bara om ingen nyare version finns i loggen.", ip)
    conn.commit()
    conn.close()
    print(f"[+] Attackyta: underdomäner kontrollerade, {findings} nya fynd.")
    return findings


def run_attack_surface(db_path: str = DB_PATH) -> int:
    """Körs från agent.py. Fel i en del stoppar inte den andra."""
    total = 0
    try:
        total += run_host_scan(db_path)
    except Exception as e:
        print(f"    Attackyta, IP-delen: {type(e).__name__}: {e}", file=sys.stderr)
    try:
        total += run_domain_scan(db_path)
    except Exception as e:
        print(f"    Attackyta, domändelen: {type(e).__name__}: {e}", file=sys.stderr)
    return total


# ------------------------------------------------------------------ larm och visning
def surface_alerts(db_path: str = DB_PATH) -> list:
    try:
        conn = _connect(db_path)
        rows = conn.execute(
            "SELECT key, level, title, detail FROM surface_findings WHERE status = 'öppen' AND level IN ('Kritisk', 'Hög', 'Medel')").fetchall()
        conn.close()
    except sqlite3.Error:
        return []
    return [{"kind": "surface", "level": l, "title": t, "detail": d, "key": "surface:" + k} for k, l, t, d in rows]


SURFACE_CSS = """
  .su-sum { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 0.5rem; margin-bottom: 0.9rem; }
  .su-sum div { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 6px; padding: 0.5rem 0.7rem; }
  .su-sum b { display: block; font-size: 1.2rem; font-family: var(--mono, monospace); } .su-sum .bad b { color: var(--red); }
  .su-sum span { font-size: 0.72rem; color: var(--text-dim); }
  .su-table { width: 100%; border-collapse: collapse; font-size: 0.83rem; margin-bottom: 0.8rem; }
  .su-table th { text-align: left; font-weight: 500; color: var(--text-dim); font-size: 0.74rem; padding: 0.3rem 0.5rem; border-bottom: 1px solid var(--panel-border); }
  .su-table td { padding: 0.3rem 0.5rem; border-bottom: 1px solid var(--panel-border); vertical-align: top; }
  .su-table td.m { font-family: var(--mono, monospace); }
  .su-h { font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-dim); margin: 0.9rem 0 0.4rem; }
"""


def build_surface_html(db_path: str = DB_PATH) -> str:
    if not (ORG["ip_ranges"] or ORG["domains"]):
        return '<p class="empty">Ingen yta konfigurerad. Fyll i config_org.py (domäner och IP-intervall).</p>'
    try:
        conn = _connect(db_path)
        total_ips = len(all_ips())
        hosts = conn.execute("SELECT ip, ports, vulns, hostnames, checked_at FROM surface_hosts").fetchall()
        findings = conn.execute(
            "SELECT level, title, detail, first_seen, status FROM surface_findings ORDER BY "
            "CASE level WHEN 'Kritisk' THEN 0 WHEN 'Hög' THEN 1 WHEN 'Medel' THEN 2 ELSE 3 END, first_seen DESC").fetchall()
        subs = conn.execute("SELECT name, first_seen, not_after, resolved_ip FROM surface_domains ORDER BY first_seen DESC").fetchall()
        conn.close()
    except sqlite3.Error:
        return '<p class="empty">Attackytan har inte kontrollerats ännu, fylls efter nästa körning.</p>'
    if not hosts and not subs:
        return '<p class="empty">Attackytan har inte kontrollerats ännu, fylls efter nästa körning.</p>'
    with_ports = [h for h in hosts if json.loads(h[1] or "[]")]
    open_f = [f for f in findings if f[4] == "öppen"]
    crit = sum(1 for f in open_f if f[0] == "Kritisk")
    port_count = sum(len(json.loads(h[1] or "[]")) for h in hosts)
    h = (
        f'<div class="su-sum"><div><b>{len(hosts)}</b><span>av {total_ips} IP-adresser kontrollerade</span></div>'
        f'<div><b>{len(with_ports)}</b><span>värdar med öppna portar</span></div><div><b>{port_count}</b><span>öppna portar totalt</span></div>'
        f'<div class="{"bad" if crit else ""}"><b>{crit}</b><span>kritiska fynd</span></div>'
        f'<div><b>{len(open_f)}</b><span>öppna fynd</span></div><div><b>{len(subs)}</b><span>underdomäner</span></div></div>'
    )
    if open_f:
        h += '<div class="su-h">Öppna fynd</div><table class="su-table"><tr><th>Nivå</th><th>Fynd</th><th>Upptäckt</th></tr>' + "".join(
            f'<tr><td><span class="in-badge {html.escape(l)}">{html.escape(l)}</span></td><td>{html.escape(t)}<div class="dim" style="font-size:0.74rem">{html.escape(d)}</div></td><td>{html.escape(fs[:10])}</td></tr>'
            for l, t, d, fs, _s in open_f[:40]) + "</table>"
    else:
        h += '<p class="dim">Inga öppna fynd hittills.</p>'
    if with_ports:
        h += '<div class="su-h">Värdar med öppna portar</div><table class="su-table"><tr><th>IP</th><th>Portar</th><th>Värdnamn</th><th>Sårbarheter</th></tr>' + "".join(
            f'<tr><td class="m">{html.escape(ip)}</td><td class="m">{html.escape(", ".join(str(p) for p in json.loads(ports)))}</td>'
            f'<td>{html.escape(", ".join(json.loads(hn or "[]")[:3]))}</td><td class="m">{html.escape(", ".join(json.loads(vu or "[]")[:4])) or "–"}</td></tr>'
            for ip, ports, vu, hn, _c in with_ports[:40]) + "</table>"
    if subs:
        h += '<div class="su-h">Underdomäner (certifikatloggen)</div><table class="su-table"><tr><th>Namn</th><th>Först sedd</th><th>Certifikat till</th><th>IP</th></tr>' + "".join(
            f'<tr><td>{html.escape(n)}</td><td>{html.escape((fs or "")[:10])}</td><td>{html.escape(na or "")}</td><td class="m">{html.escape(ip or "")}</td></tr>'
            for n, fs, na, ip in subs[:30]) + "</table>"
    return h + (
        f'<p class="dim" style="font-size:0.78rem;white-space:normal">Data från Shodan InternetDB och certifikatloggar (inga egna skanningar). '
        f'{SURFACE_IPS_PER_RUN} IP-adresser kontrolleras per körning, hela intervallet tar alltså flera körningar. '
        f'Organisation: {html.escape(ORG["name"])} ({html.escape(", ".join(ORG["asns"]))}).</p>')


if __name__ == "__main__":
    run_attack_surface()
