"""
Berikar CVE:er som redan hittats (via regex i RSS-artiklar) med data från
Shodans CVEDB — ett helt gratis, nyckellöst API. Detta löser ett verkligt
problem: att bara VETA att en artikel nämner "CVE-2026-1234" säger inget
om hur farlig den faktiskt är. CVEDB ger:

- EPSS: sannolikheten (0-1) att sårbarheten utnyttjas inom 30 dagar
- KEV: om CISA bekräftat att den redan aktivt utnyttjas i verkliga attacker
- Koppling till kända ransomware-kampanjer, om sådan finns

En CVE med hög EPSS + KEV = true är mycket mer akut än en CVE med låg
EPSS och ingen känd exploatering, oavsett CVSS-poäng.

Dokumentation: https://cvedb.shodan.io/
"""

import sys
import time

import requests

from storage import get_conn, get_unenriched_cves, save_cve_enrichment

CVEDB_URL = "https://cvedb.shodan.io/cve/{cve_id}"

MAX_LOOKUPS_PER_RUN = 30
DELAY_BETWEEN_CALLS = 0.5


def lookup_cve(cve_id: str) -> dict | None:
    try:
        resp = requests.get(CVEDB_URL.format(cve_id=cve_id), timeout=15)
    except requests.RequestException as e:
        print(f"    Fel vid CVEDB-uppslag av {cve_id}: {e}", file=sys.stderr)
        return None

    if resp.status_code == 404:
        return None  # okänd CVE i CVEDB, ovanligt men kan hända för mycket nya CVE:er

    if resp.status_code != 200:
        print(f"    CVEDB svarade {resp.status_code} för {cve_id}", file=sys.stderr)
        return None

    try:
        return resp.json()
    except ValueError:
        return None


def run_cve_enrichment() -> list:
    """
    Berikar nya CVE:er. Returnerar en lista över de som visade sig vara
    akuta (KEV=True eller EPSS >= 0.5), för användning i notiser.
    """
    cve_ids = get_unenriched_cves(limit=MAX_LOOKUPS_PER_RUN)
    if not cve_ids:
        return []

    print(f"[+] Shodan CVEDB: prioriterar {len(cve_ids)} nya CVE:er ...")
    urgent = []

    with get_conn() as conn:
        for cve_id in cve_ids:
            data = lookup_cve(cve_id)
            if data:
                kev = bool(data.get("kev"))
                epss = data.get("epss") or 0.0
                ransomware = data.get("ransomware_campaign")

                save_cve_enrichment(
                    conn,
                    cve_id=cve_id,
                    cvss=data.get("cvss"),
                    epss=epss,
                    kev=kev,
                    ransomware_campaign=ransomware,
                    summary=(data.get("summary") or "")[:500],
                )

                if kev or epss >= 0.5:
                    urgent.append({
                        "cve_id": cve_id, "epss": epss, "kev": kev,
                        "ransomware_campaign": ransomware,
                    })
                    flag = "KEV" if kev else f"EPSS {epss:.0%}"
                    print(f"    ⚠ {cve_id}: {flag} — aktivt riskfylld")

            time.sleep(DELAY_BETWEEN_CALLS)

    print(f"    CVEDB: {len(cve_ids)} CVE:er berikade, {len(urgent)} akuta")
    return urgent


if __name__ == "__main__":
    run_cve_enrichment()
