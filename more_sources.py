"""
Fler källor, alla gratis:

  1. CISA KEV  – katalogen över aktivt utnyttjade sårbarheter (JSON, ingen nyckel)
  2. abuse.ch URLhaus – skadliga URL:er (kräver samma THREATFOX_AUTH_KEY)
  3. abuse.ch Feodo Tracker – botnet-C2-IP:er (JSON, ingen nyckel)
  4. Extra RSS-flöden – leverantörsbloggar och fler nationella CERT:er

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
from extract import extract_iocs

TIMEOUT = 25
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_LOOKBACK_DAYS = 30          # första körningen tar inte in hela katalogen (~1400 poster)
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/"
URLHAUS_LIMIT = 200
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
FEODO_FEED = "ThreatFox · Feodo Tracker"
URLHAUS_FEED = "ThreatFox · URLhaus"

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
    try:
        resp = requests.get(KEV_URL, timeout=TIMEOUT, headers={"User-Agent": "cti-agent"})
        resp.raise_for_status()
        entries = parse_kev(resp.json())
    except Exception as e:
        print(f"    CISA KEV: kunde inte hämta ({e})", file=sys.stderr)
        return []

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
        return 0
    try:
        resp = requests.get(
            URLHAUS_URL.format(limit=URLHAUS_LIMIT), timeout=TIMEOUT,
            headers={"Auth-Key": key, "User-Agent": "cti-agent"},
        )
        resp.raise_for_status()
        ioc_map = parse_urlhaus(resp.json())
    except Exception as e:
        print(f"    URLhaus: kunde inte hämta ({e})", file=sys.stderr)
        return 0

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
    try:
        resp = requests.get(FEODO_URL, timeout=TIMEOUT, headers={"User-Agent": "cti-agent"})
        resp.raise_for_status()
        ioc_map = parse_feodo(resp.json())
    except Exception as e:
        print(f"    Feodo Tracker: kunde inte hämta ({e})", file=sys.stderr)
        return 0

    with get_conn() as conn:
        seen = _existing_values(conn, FEODO_FEED)
        ioc_map = {t: sorted({v for v in vals if v not in seen}) for t, vals in ioc_map.items()}
        count = _store_pull(conn, FEODO_FEED, "Feodo Tracker", ioc_map)
    print(f"[+] Feodo Tracker: {count} nya botnet-C2-IP:er")
    return count


# ---------------------------------------------------------------- Extra RSS
def run_extra_feeds() -> int:
    total_new = 0
    with get_conn() as conn:
        for feed in EXTRA_FEEDS:
            try:
                parsed = feedparser.parse(feed["url"], agent="Mozilla/5.0 (cti-agent)")
            except Exception as e:
                print(f"    {feed['name']}: fel vid hämtning ({e})", file=sys.stderr)
                continue
            if parsed.bozo and not parsed.entries:
                print(f"    {feed['name']}: kunde inte tolka flödet", file=sys.stderr)
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
            print(f"[+] {feed['name']}: {new_here} nya artiklar")
    return total_new


# ---------------------------------------------------------------- Samlad körning
def run_more_sources() -> dict:
    """Kör alla extra källor. Returnerar en dict som agent.py kan använda i notiser."""
    result = {"kev": [], "urlhaus": 0, "feodo": 0, "rss": 0}
    for name, fn in (("kev", run_kev), ("urlhaus", run_urlhaus), ("feodo", run_feodo), ("rss", run_extra_feeds)):
        try:
            result[name] = fn()
        except Exception as e:  # sista skyddsnätet — en källa får aldrig fälla agenten
            print(f"    {name}: oväntat fel ({e})", file=sys.stderr)
    return result


if __name__ == "__main__":
    from storage import init_db
    init_db()
    print(run_more_sources())
