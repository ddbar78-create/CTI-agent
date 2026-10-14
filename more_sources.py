"""
Fler källor, alla gratis:

  1. CISA KEV  – katalogen över aktivt utnyttjade sårbarheter (JSON, ingen nyckel)
  2. abuse.ch URLhaus – skadliga URL:er (kräver samma THREATFOX_AUTH_KEY)
  3. abuse.ch Feodo Tracker – botnet-C2-IP:er (JSON, ingen nyckel)
  4. Extra RSS-flöden – leverantörsbloggar och fler nationella CERT:er
  5. abuse.ch MalwareBazaar – färska malware-hashar med familj (samma nyckel)
  6. AlienVault OTX – kampanj-"pulser" med aktör, ATT&CK och IOC:er (gratis
     nyckel i secret OTX_API_KEY; hoppas över om den saknas)

Varje källa är isolerad: ett fel (nät, ändrat format) skriver en rad i loggen
och hoppar över just den källan — agenten fortsätter alltid.
URLhaus/Feodo-IOCs sparas under feed-namn som börjar på "ThreatFox" så att
de följer samma regler som ThreatFox (7 dagars retention, döljs från
artikellistan, ATT&CK-mappas via familjenamnet).
"""

import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone

import feedparser
import requests

from storage import get_conn, save_article, save_iocs
from run_status import record
from extract import extract_iocs

TIMEOUT = 25
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_LOOKBACK_DAYS = 30          # första körningen tar inte in hela katalogen (~1400 poster)
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/"
URLHAUS_LIMIT = 200
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
FEODO_FEED = "ThreatFox · Feodo Tracker"
URLHAUS_FEED = "ThreatFox · URLhaus"
MB_URL = "https://mb-api.abuse.ch/api/v1/"
MB_FEED = "ThreatFox · MalwareBazaar"
MB_LIMIT = 200
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
OTX_FEED = "AlienVault OTX"
OTX_PULSES = 20
OTX_MAX_IOCS_PER_PULSE = 150
OTX_LOOKBACK_DAYS = 7

EXTRA_FEEDS = [
    {"name": "Microsoft Security Blog", "url": "https://www.microsoft.com/en-us/security/blog/feed/"},
    {"name": "Google Threat Intelligence (Mandiant)", "url": "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/"},
    {"name": "Cisco Talos", "url": "https://blog.talosintelligence.com/rss/"},
    {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/"},
    {"name": "ESET WeLiveSecurity", "url": "https://www.welivesecurity.com/en/rss/feed/"},
    {"name": "Securelist (Kaspersky)", "url": "https://securelist.com/feed/"},
    {"name": "The DFIR Report", "url": "https://thedfirreport.com/feed/"},
    {"name": "SecurityWeek", "url": "https://feeds.feedburner.com/securityweek"},
    {"name": "NCSC-NL (Nederländerna)", "url": "https://advisories.ncsc.nl/rss/advisories"},
]
MAX_NEW_PER_FEED = 15

_FILETYPE_TAGS = {
    "elf", "exe", "zip", "dll", "ps1", "js", "doc", "docx", "xls", "xlsx", "pdf", "sh",
    "bat", "apk", "msi", "rar", "7z", "iso", "lnk", "vbs", "jar", "dmg", "pkg", "opendir",
    "32-bit", "64-bit", "arm", "mips", "mipsel", "x86", "powerpc",
}


def _existing_values(conn, feed: str) -> set:
    cur = conn.execute(
        "SELECT iocs.value FROM iocs JOIN articles ON articles.id = iocs.article_id WHERE articles.feed = ?",
        (feed,),
    )
    return {r[0] for r in cur.fetchall()}


def _store_pull(conn, feed: str, label: str, ioc_map: dict) -> int:
    """Sparar en samling nya IOCs som en 'pull'-artikel, precis som ThreatFox gör."""
    total = sum(len(v) for v in ioc_map.values())
    if not total:
        return 0
    ts = int(time.time())
    article_id = save_article(
        conn, feed, f"{label} IOC-hämtning ({total} poster)", f"{feed.split('· ')[-1].lower().replace(' ', '')}-pull-{ts}",
        datetime.now(timezone.utc).strftime("%Y-%m-%d"), f"{total} nya indikatorer från {label}.",
    )
    if article_id is None:
        return 0
    save_iocs(conn, article_id, ioc_map)
    return total


# ---------------------------------------------------------------- CISA KEV
def parse_kev(data: dict, lookback_days: int = KEV_LOOKBACK_DAYS, now=None) -> list:
    """Returnerar nya KEV-poster (dict) tillagda inom lookback-fönstret."""
    now = now or datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=lookback_days)).strftime("%Y-%m-%d")
    out = []
    for v in data.get("vulnerabilities", []):
        if not v.get("cveID") or (v.get("dateAdded") or "") < cutoff:
            continue
        out.append(v)
    return out


def run_kev() -> list:
    resp = requests.get(KEV_URL, timeout=TIMEOUT, headers={"User-Agent": "cti-agent"})
    resp.raise_for_status()
    entries = parse_kev(resp.json())

    new_entries = []
    with get_conn() as conn:
        for v in entries:
            cve = v["cveID"].upper()
            ransomware = (v.get("knownRansomwareCampaignUse") or "").lower() == "known"
            title = f"KEV: {cve} – {v.get('vendorProject', '')} {v.get('product', '')} ({v.get('vulnerabilityName', '')})".strip()
            summary = (
                f"{v.get('shortDescription', '')} Åtgärd: {v.get('requiredAction', '')} "
                f"Tillagd i KEV: {v.get('dateAdded', '')}."
                + (" Används i ransomware-kampanjer." if ransomware else "")
            )
            article_id = save_article(
                conn, "CISA KEV", title, f"https://nvd.nist.gov/vuln/detail/{cve}",
                v.get("dateAdded", ""), summary,
            )
            if article_id is None:
                continue  # redan känd
            save_iocs(conn, article_id, {"cve": [cve]})
            new_entries.append({"cve_id": cve, "ransomware": ransomware, "title": title})
    print(f"[+] CISA KEV: {len(new_entries)} nya aktivt utnyttjade sårbarheter")
    return new_entries


# ---------------------------------------------------------------- URLhaus
def parse_urlhaus(data: dict) -> dict:
    """Returnerar {'url': [värden], 'domain': [värden]} i ThreatFox-format."""
    urls, domains = [], []
    for u in data.get("urls") or []:
        url = (u.get("url") or "").strip()
        if not url or (u.get("url_status") and u["url_status"] != "online"):
            continue
        tags = [t for t in (u.get("tags") or []) if t and t.lower() not in _FILETYPE_TAGS]
        family = tags[0] if tags else "URLhaus"
        urls.append(f"{url}  [{family}, confidence 90]")
        host = (u.get("host") or "").strip()
        if host and not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            domains.append(f"{host}  [{family}, confidence 90]")
    return {"url": urls, "domain": domains}


def run_urlhaus() -> int:
    key = os.environ.get("THREATFOX_AUTH_KEY", "").strip()
    if not key:
        print("    URLhaus: ingen THREATFOX_AUTH_KEY satt, hoppar över.")
        return None
    resp = requests.get(
        URLHAUS_URL.format(limit=URLHAUS_LIMIT), timeout=TIMEOUT,
        headers={"Auth-Key": key, "User-Agent": "cti-agent"},
    )
    resp.raise_for_status()
    ioc_map = parse_urlhaus(resp.json())

    with get_conn() as conn:
        seen = _existing_values(conn, URLHAUS_FEED)
        ioc_map = {t: sorted({v for v in vals if v not in seen}) for t, vals in ioc_map.items()}
        count = _store_pull(conn, URLHAUS_FEED, "URLhaus", ioc_map)
    print(f"[+] URLhaus: {count} nya IOCs")
    return count


# ---------------------------------------------------------------- Feodo
def parse_feodo(data) -> dict:
    entries = data if isinstance(data, list) else data.get("blocklist", [])
    values = []
    for e in entries:
        ip = (e.get("ip_address") or e.get("ip") or "").strip()
        if not ip:
            continue
        if e.get("status") and str(e["status"]).lower() != "online":
            continue
        port = e.get("port")
        family = e.get("malware") or "Feodo"
        values.append(f"{ip}:{port}  [{family}, confidence 90]" if port else f"{ip}  [{family}, confidence 90]")
    return {"ip:port": values}


def run_feodo() -> int:
    resp = requests.get(FEODO_URL, timeout=TIMEOUT, headers={"User-Agent": "cti-agent"})
    resp.raise_for_status()
    ioc_map = parse_feodo(resp.json())

    with get_conn() as conn:
        seen = _existing_values(conn, FEODO_FEED)
        ioc_map = {t: sorted({v for v in vals if v not in seen}) for t, vals in ioc_map.items()}
        count = _store_pull(conn, FEODO_FEED, "Feodo Tracker", ioc_map)
    print(f"[+] Feodo Tracker: {count} nya botnet-C2-IP:er")
    return count


# ---------------------------------------------------------------- MalwareBazaar
def parse_malwarebazaar(data: dict) -> dict:
    """Returnerar {'sha256_hash': [...], 'sha1_hash': [...], 'md5_hash': [...]} i ThreatFox-format."""
    if data.get("query_status") != "ok":
        raise RuntimeError(f"MalwareBazaar svarade: {data.get('query_status')}")
    out = {"sha256_hash": [], "sha1_hash": [], "md5_hash": []}
    for e in (data.get("data") or [])[:MB_LIMIT]:
        tags = [t for t in (e.get("tags") or []) if t and t.lower() not in _FILETYPE_TAGS]
        family = e.get("signature") or (tags[0] if tags else "MalwareBazaar")
        for field, key in (("sha256_hash", "sha256_hash"), ("sha1_hash", "sha1_hash"), ("md5_hash", "md5_hash")):
            if e.get(field):
                out[key].append(f"{e[field].lower()}  [{family}, confidence 90]")
    return out


def run_malwarebazaar():
    key = os.environ.get("THREATFOX_AUTH_KEY", "").strip()
    if not key:
        return None
    resp = requests.post(
        MB_URL, data={"query": "get_recent", "selector": "time"}, timeout=TIMEOUT,
        headers={"Auth-Key": key, "User-Agent": "cti-agent"},
    )
    resp.raise_for_status()
    ioc_map = parse_malwarebazaar(resp.json())
    with get_conn() as conn:
        seen = _existing_values(conn, MB_FEED)
        ioc_map = {t: sorted({v for v in vals if v not in seen}) for t, vals in ioc_map.items()}
        count = _store_pull(conn, MB_FEED, "MalwareBazaar", ioc_map)
    print(f"[+] MalwareBazaar: {count} nya IOCs")
    return count


# ---------------------------------------------------------------- AlienVault OTX
_OTX_TYPES = {
    "IPv4": "ipv4", "domain": "domain", "hostname": "domain", "URL": "url",
    "FileHash-SHA256": "sha256_hash", "FileHash-SHA1": "sha1_hash", "FileHash-MD5": "md5_hash",
    "CVE": "cve",
}


def parse_otx_pulse(p: dict):
    """Returnerar (titel, länk, sammanfattning, ioc_map) för en OTX-puls."""
    def _attack(a):
        if isinstance(a, dict):
            return f"{a.get('id', '')} {a.get('name') or a.get('display_name') or ''}".strip()
        return str(a).strip()

    attack = ", ".join(x for x in (_attack(a) for a in (p.get("attack_ids") or [])[:12]) if x)
    parts = [(p.get("description") or "")[:500]]
    if p.get("adversary"):
        parts.append(f"Aktör: {p['adversary']}.")
    if p.get("targeted_countries"):
        parts.append("Mål-länder: " + ", ".join(str(x) for x in p["targeted_countries"][:10]) + ".")
    if p.get("industries"):
        parts.append("Branscher: " + ", ".join(str(x) for x in p["industries"][:10]) + ".")
    if p.get("tags"):
        parts.append("Taggar: " + ", ".join(str(x) for x in p["tags"][:12]) + ".")
    if attack:
        parts.append("ATT&CK: " + attack + ".")
    ioc_map = {}
    for ind in (p.get("indicators") or [])[:OTX_MAX_IOCS_PER_PULSE]:
        if not isinstance(ind, dict):
            continue
        t = _OTX_TYPES.get(ind.get("type"))
        v = (ind.get("indicator") or "").strip()
        if t and v:
            ioc_map.setdefault(t, []).append(v.upper() if t == "cve" else v)
    return (
        f"OTX: {p.get('name', '')}".strip(),
        f"https://otx.alienvault.com/pulse/{p.get('id')}",
        " ".join(x for x in parts if x),
        ioc_map,
    )


def run_otx():
    key = os.environ.get("OTX_API_KEY", "").strip()
    if not key:
        return None
    since = (datetime.now(timezone.utc) - timedelta(days=OTX_LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%S")
    resp = requests.get(
        OTX_URL, params={"limit": OTX_PULSES, "modified_since": since}, timeout=TIMEOUT,
        headers={"X-OTX-API-KEY": key, "User-Agent": "cti-agent"},
    )
    resp.raise_for_status()
    new_pulses = 0
    with get_conn() as conn:
        for p in resp.json().get("results", []):
            if not p.get("id"):
                continue
            title, link, summary, ioc_map = parse_otx_pulse(p)
            article_id = save_article(conn, OTX_FEED, title, link, (p.get("modified") or "")[:10], summary)
            if article_id is None:
                continue
            new_pulses += 1
            if ioc_map:
                save_iocs(conn, article_id, ioc_map)
    print(f"[+] AlienVault OTX: {new_pulses} nya pulser")
    return new_pulses


# ---------------------------------------------------------------- Extra RSS
def run_extra_feeds() -> int:
    total_new = 0
    statuses = []  # (namn, ok, antal, fel) — sparas efter att databastransaktionen stängts
    with get_conn() as conn:
        for feed in EXTRA_FEEDS:
            try:
                parsed = feedparser.parse(feed["url"], agent="Mozilla/5.0 (cti-agent)")
            except Exception as e:
                print(f"    {feed['name']}: fel vid hämtning ({e})", file=sys.stderr)
                statuses.append((feed["name"], 0, 0, str(e)))
                continue
            if parsed.bozo and not parsed.entries:
                print(f"    {feed['name']}: kunde inte tolka flödet", file=sys.stderr)
                statuses.append((feed["name"], 0, 0, "kunde inte tolka flödet"))
                continue
            new_here = 0
            for entry in parsed.entries:
                if new_here >= MAX_NEW_PER_FEED:
                    break
                title = entry.get("title", "")
                link = entry.get("link", "")
                if not link:
                    continue
                summary = entry.get("summary", "") or entry.get("description", "")
                article_id = save_article(conn, feed["name"], title, link, entry.get("published", ""), summary)
                if article_id is None:
                    continue
                new_here += 1
                iocs = extract_iocs(f"{title}\n{summary}")
                if iocs:
                    save_iocs(conn, article_id, iocs)
            total_new += new_here
            statuses.append((feed["name"], 1, new_here, ""))
            print(f"[+] {feed['name']}: {new_here} nya artiklar")
    for name, ok, n, err in statuses:
        record(name, ok, n, err)
    return total_new


# ---------------------------------------------------------------- Samlad körning
def run_more_sources() -> dict:
    """
    Kör alla extra källor och registrerar status per källa. Returnerar en dict
    som agent.py kan använda i notiser. En källa som fallerar fäller aldrig agenten.
    """
    result = {"kev": [], "urlhaus": 0, "feodo": 0, "rss": 0, "mbazaar": 0, "otx": 0}
    sources = (
        ("kev", "CISA KEV", run_kev),
        ("urlhaus", "URLhaus", run_urlhaus),
        ("feodo", "Feodo Tracker", run_feodo),
        ("mbazaar", "MalwareBazaar", run_malwarebazaar),
        ("otx", "AlienVault OTX", run_otx),
    )
    for key, label, fn in sources:
        try:
            out = fn()
        except Exception as e:
            print(f"    {label}: kunde inte hämta ({e})", file=sys.stderr)
            record(label, 0, 0, str(e))
            continue
        if out is None:  # ej konfigurerad (saknar nyckel)
            record(label, -1, 0, "ej konfigurerad")
            continue
        result[key] = out
        record(label, 1, len(out) if isinstance(out, list) else int(out))
    try:
        result["rss"] = run_extra_feeds()  # sparar status per flöde själv
    except Exception as e:
        print(f"    Extra RSS: oväntat fel ({e})", file=sys.stderr)
    return result


if __name__ == "__main__":
    from storage import init_db
    init_db()
    print(run_more_sources())
