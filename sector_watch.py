"""
Låter dig bevaka specifika sektorer/branscher bland redan insamlad data —
ransomware-offer (sektorfält + offernamn) och RSS/Telegram-artiklar
(titel/sammanfattning/fulltext) — samt märka vad som är NORDISKT.

Ren nyckelordsmatchning, ingen extern källa eller nyckel behövs. Filen är
tänkt att redigeras: lägg till sektorer och nyckelord efter eget intresse.

MATCHNINGSREGLER (viktigt när du lägger till egna nyckelord):
  * Ett nyckelord matchar bara från BÖRJAN av ett ord. "kommune" träffar
    "kommunen" och "kommuner", men "port" skulle aldrig träffa "report"
    eller "support" (som en enkel delsträngsmatchning gjorde tidigare).
  * Lägg ett utropstecken sist för att kräva HELT ord: "bank!" träffar
    "bank" men inte "banking" eller "bankrupt".
  * Flerordsfraser fungerar: "port authority", "oil and gas".
  * Undvik korta, tvetydiga ord som också är vanliga i säkerhetsnyheter
    (t.ex. "pipeline" pga CI/CD, "gas" pga krypto, "portal", "rails").
"""

import re

WATCHED_SECTORS = {
    # De första i listan visas högst upp på dashboarden.
    "Transport & logistik": [
        "transportation", "transport sector", "transport company",
        "transport industry", "transport and logistics", "transport & logistics",
        "public transport", "transportsektor", "transportföretag",
        "transportstyrelsen", "trafiksektor", "trafikverket", "kollektivtrafik",
        "logistic", "logistik", "freight", "cargo", "haulage", "trucking",
        "fraktbolag", "spedition", "godstransport",
        "shipping company", "shipping line", "shipping industry", "shipping firm",
        "maritime", "sjöfart", "rederi", "seaport", "port authority", "port of",
        "harbor", "harbour", "hamnen", "havn", "ferry", "färj", "færge", "ferje",
        "railway", "railroad", "rail network", "rail operator", "train operator",
        "järnväg", "jernbane", "tåg",
        "aviation", "airline", "airport", "flygplats", "flygbolag", "luftfart",
        "lufthavn", "flyplass", "flyg",
        "maersk", "dfds", "postnord", "finnair", "widerøe",
    ],
    "Offentlig sektor": [
        "public sector", "public authority", "public administration",
        "state agency", "civil service", "ministry", "government",
        "municipal", "municipality", "kommune", "kommunal", "myndighet",
        "länsstyrelse", "regeringen", "regjering", "riksdag", "storting",
        "folketing", "eduskunta", "fylke", "landsting", "county council",
        "county government", "county of", "city of", "town of", "village of",
        "department of", "school district",
        "region skåne", "region stockholm", "region uppsala",
        "polisen", "polismyndigheten", "politiet", "police",
        "skatteverket", "försäkringskassan", "arbetsförmedlingen",
    ],
    "Sjukvård": [
        "healthcare", "health care", "hospital", "sjukvård", "sjukhus",
        "sykehus", "medical", "clinic", "vårdcentral", "pharma", "läkemedel",
        "patient",
    ],
    "Energi": [
        "energy", "energi", "electricity", "power grid", "power plant",
        "kraftverk", "elnät", "kärnkraft", "nuclear", "oil and gas",
        "oil & gas", "oil company", "oil refinery", "natural gas",
        "gas pipeline", "fuel pipeline", "utility company", "power utility",
        "water utility", "utilities provider",
        "vattenfall", "equinor", "fortum", "statkraft", "ørsted", "orsted",
    ],
    "Finans": [
        "bank!", "banks!", "banking sector", "banking industry",
        "banking customers", "online banking", "bankid",
        "financial sector", "financial services", "financial institution",
        "financial industry", "finance sector", "finance industry", "finans",
        "insurance", "försäkring", "fintech", "credit union",
        "payment provider",
        "swedbank", "handelsbanken", "nordea", "danske bank",
    ],
    # Lägg till fler sektorer här efter eget behov, t.ex.:
    # "Utbildning": ["school", "university", "skola", "universitet"],
    # "Detaljhandel": ["retail", "detaljhandel", "e-commerce"],
}

# --- Nordisk igenkänning ---------------------------------------------------

# Landskoder (ISO) som räknas som nordiska — används på ransomware-offer.
NORDIC_COUNTRY_CODES = {"SE", "NO", "DK", "FI", "IS"}

# Källor som i sig är nordiska myndigheter (namnen måste matcha feeds.py).
NORDIC_FEED_NAMES = {
    "CERT-SE (Sverige)", "NSM NCSC (Norge)", "DKCERT (Danmark)",
    "NCSC-FI (Finland)",
}

# Termer i artikeltext som markerar nordiskt sammanhang.
NORDIC_TERMS = [
    "sweden", "swedish", "sverige", "svensk",
    "norway", "norwegian", "norge", "norsk",
    "denmark", "danish", "danmark", "dansk",
    "finland", "finnish", "suomi",
    "iceland", "icelandic",
    "nordic", "norden", "nordisk", "scandinavia", "scandinavian", "skandinavien",
    "stockholm", "oslo", "copenhagen", "köpenhamn", "helsinki", "reykjavik",
    "göteborg", "gothenburg", "malmö",
    "cert-se", "ncsc-fi", "kyberturvallisuuskeskus", "cfcs", "nsm.no",
]


def _build_pattern(keywords: list):
    """Bygger ett regex som matchar nyckelord från ordets början
    (eller hela ord om nyckelordet slutar med '!')."""
    parts = []
    for kw in keywords:
        if kw.endswith("!"):
            parts.append(re.escape(kw[:-1]) + r"\b")
        else:
            parts.append(re.escape(kw))
    return re.compile(r"\b(?:" + "|".join(parts) + ")", re.IGNORECASE)


_SECTOR_PATTERNS = {s: _build_pattern(kws) for s, kws in WATCHED_SECTORS.items()}
_NORDIC_PATTERN = _build_pattern(NORDIC_TERMS)


def classify_sector(text: str) -> list:
    """
    Returnerar en lista med namnen på alla bevakade sektorer vars
    nyckelord matchar i texten (en text kan höra till flera sektorer).
    """
    if not text:
        return []
    return [s for s, pattern in _SECTOR_PATTERNS.items() if pattern.search(text)]


def is_nordic_country(code) -> bool:
    return (code or "").strip().upper() in NORDIC_COUNTRY_CODES


def is_nordic_article(feed: str, text: str) -> bool:
    """Nordisk om källan är en nordisk myndighet eller texten nämner Norden."""
    if feed in NORDIC_FEED_NAMES:
        return True
    return bool(text and _NORDIC_PATTERN.search(text))
