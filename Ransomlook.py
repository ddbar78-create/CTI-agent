"""
RansomLook — extra källa för ransomware-offer, som komplement till ransomware.live.

API: https://www.ransomlook.io/api/recent (JSON, senaste 100 inläggen, öppet, ingen nyckel).
Fält som används: post_title (offret), group_name, discovered, description
("bransch · plats", t.ex. "Accounting & Tax Preparation (US) · Massachusetts, USA").

Offren sparas i samma tabell som ransomware.live (ransomware_victims) och syns
därmed i kartan, dagsrapporten och bevakningslistan. Dubbletter mot redan
sparade offer (samma grupp + offer, eller samma offer och datum) hoppas över.
"""

import sys

import requests

from storage import get_conn, save_ransomware_victim

URL = "https://www.ransomlook.io/api/recent"
TIMEOUT = 40

# Landsnamn (engelska, gemener) -> ISO-3166 alpha-2, i samma format som ransomware.live använder.
_COUNTRIES = {
    "afghanistan": "AF", "albania": "AL", "algeria": "DZ", "andorra": "AD", "angola": "AO", "argentina": "AR",
    "armenia": "AM", "australia": "AU", "austria": "AT", "azerbaijan": "AZ", "bahamas": "BS", "bahrain": "BH",
    "bangladesh": "BD", "barbados": "BB", "belarus": "BY", "belgium": "BE", "belize": "BZ", "benin": "BJ",
    "bermuda": "BM", "bhutan": "BT", "bolivia": "BO", "bosnia and herzegovina": "BA", "botswana": "BW",
    "brazil": "BR", "brunei": "BN", "bulgaria": "BG", "burkina faso": "BF", "cambodia": "KH", "cameroon": "CM",
    "canada": "CA", "cape verde": "CV", "cayman islands": "KY", "chile": "CL", "china": "CN", "colombia": "CO",
    "congo": "CG", "costa rica": "CR", "croatia": "HR", "cuba": "CU", "cyprus": "CY", "czech republic": "CZ",
    "czechia": "CZ", "denmark": "DK", "dominican republic": "DO", "ecuador": "EC", "egypt": "EG",
    "el salvador": "SV", "estonia": "EE", "ethiopia": "ET", "fiji": "FJ", "finland": "FI", "france": "FR",
    "gabon": "GA", "georgia": "GE", "germany": "DE", "ghana": "GH", "gibraltar": "GI", "greece": "GR",
    "guatemala": "GT", "guernsey": "GG", "haiti": "HT", "honduras": "HN", "hong kong": "HK", "hungary": "HU",
    "iceland": "IS", "india": "IN", "indonesia": "ID", "iran": "IR", "iraq": "IQ", "ireland": "IE",
    "isle of man": "IM", "israel": "IL", "italy": "IT", "ivory coast": "CI", "jamaica": "JM", "japan": "JP",
    "jersey": "JE", "jordan": "JO", "kazakhstan": "KZ", "kenya": "KE", "kosovo": "XK", "kuwait": "KW",
    "kyrgyzstan": "KG", "laos": "LA", "latvia": "LV", "lebanon": "LB", "libya": "LY", "liechtenstein": "LI",
    "lithuania": "LT", "luxembourg": "LU", "macau": "MO", "madagascar": "MG", "malawi": "MW", "malaysia": "MY",
    "maldives": "MV", "mali": "ML", "malta": "MT", "mauritius": "MU", "mexico": "MX", "moldova": "MD",
    "monaco": "MC", "mongolia": "MN", "montenegro": "ME", "morocco": "MA", "mozambique": "MZ", "myanmar": "MM",
    "namibia": "NA", "nepal": "NP", "netherlands": "NL", "new zealand": "NZ", "nicaragua": "NI", "nigeria": "NG",
    "north macedonia": "MK", "norway": "NO", "oman": "OM", "pakistan": "PK", "palestine": "PS", "panama": "PA",
    "papua new guinea": "PG", "paraguay": "PY", "peru": "PE", "philippines": "PH", "poland": "PL",
    "portugal": "PT", "puerto rico": "PR", "qatar": "QA", "romania": "RO", "russia": "RU", "rwanda": "RW",
    "saudi arabia": "SA", "senegal": "SN", "serbia": "RS", "singapore": "SG", "slovakia": "SK", "slovenia": "SI",
    "somalia": "SO", "south africa": "ZA", "south korea": "KR", "korea": "KR", "spain": "ES", "sri lanka": "LK",
    "sudan": "SD", "suriname": "SR", "sweden": "SE", "switzerland": "CH", "syria": "SY", "taiwan": "TW",
    "tajikistan": "TJ", "tanzania": "TZ", "thailand": "TH", "togo": "TG", "trinidad and tobago": "TT",
    "tunisia": "TN", "turkey": "TR", "turkiye": "TR", "uganda": "UG", "ukraine": "UA",
    "united arab emirates": "AE", "uae": "AE", "united kingdom": "GB", "uk": "GB", "england": "GB",
    "scotland": "GB", "wales": "GB", "united states": "US", "usa": "US", "us": "US", "uruguay": "UY",
    "uzbekistan": "UZ", "venezuela": "VE", "vietnam": "VN", "yemen": "YE", "zambia": "ZM", "zimbabwe": "ZW",
}


def country_code(location: str) -> str:
    """'Massachusetts, USA' -> 'US', 'Egypt' -> 'EG'. Okänt -> '' (visas som ej utplacerat)."""
    last = (location or "").split(",")[-1].strip().lower()
    return _COUNTRIES.get(last, "")


def parse_post(post: dict):
    """Returnerar (grupp, offer, landskod, bransch, datum) eller None om inlägget saknar offer/grupp."""
    victim = (post.get("post_title") or "").strip()
    group = (post.get("group_name") or "").strip()
    if not victim or not group:
        return None
    desc = (post.get("description") or "").strip()
    sector, location = "", ""
    if " · " in desc:
        sector, location = desc.split(" · ", 1)[0].strip(), desc.rsplit(" · ", 1)[-1].strip()
    return group, victim, country_code(location), sector, (post.get("discovered") or "")[:10]


def run_ransomlook() -> int:
    resp = requests.get(URL, timeout=TIMEOUT, headers={"User-Agent": "cti-agent"})
    resp.raise_for_status()
    posts = resp.json()
    if not isinstance(posts, list):
        raise ValueError("oväntat svarsformat från RansomLook")

    new = 0
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT lower(group_name), lower(victim), attack_date FROM ransomware_victims")
        known_pair, known_day = set(), set()
        for g, v, d in cur.fetchall():
            known_pair.add((g, v))
            known_day.add((v, d))
        for post in posts:
            parsed = parse_post(post) if isinstance(post, dict) else None
            if not parsed:
                continue
            group, victim, cc, sector, day = parsed
            if (group.lower(), victim.lower()) in known_pair or (victim.lower(), day) in known_day:
                continue
            save_ransomware_victim(conn, group, victim, cc, sector, day)
            known_pair.add((group.lower(), victim.lower()))
            known_day.add((victim.lower(), day))
            new += 1
    print(f"[+] RansomLook: {new} nya offer", file=sys.stdout)
    return new
