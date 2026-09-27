"""
Låter dig bevaka specifika sektorer/branscher bland redan insamlad data —
ransomware-offer (som redan har ett sektor-/branschfält från ransomware.live)
och RSS/Telegram-artiklar (matchat mot titel/sammanfattning/fulltext).

Ren nyckelordsmatchning, ingen extern källa eller nyckel behövs. Lägg till
eller ta bort sektorer och nyckelord helt efter eget intresse — filen är
tänkt att redigeras.
"""

WATCHED_SECTORS = {
    "Transport & logistik": [
        "transport", "logistics", "logistik", "shipping", "maritime", "sjöfart",
        "railway", "rail", "tåg", "aviation", "airline", "flyg", "trucking",
        "haulage", "port", "hamn", "freight", "fraktbolag", "spedition",
    ],
    "Sjukvård": [
        "healthcare", "hospital", "sjukvård", "sjukhus", "medical", "clinic",
        "vårdcentral", "pharma", "läkemedel",
    ],
    "Energi": [
        "energy", "energi", "power grid", "kraftverk", "utility", "oil", "gas",
        "elnät", "kärnkraft", "nuclear",
    ],
    "Finans": [
        "bank", "finance", "finans", "insurance", "försäkring", "fintech",
    ],
    "Offentlig sektor": [
        "government", "myndighet", "municipality", "kommun", "county", "region",
        "public sector", "polis", "police",
    ],
    # Lägg till fler sektorer här efter eget behov, t.ex.:
    # "Utbildning": ["school", "university", "skola", "universitet"],
    # "Detaljhandel": ["retail", "detaljhandel", "e-commerce"],
}


def classify_sector(text: str) -> list:
    """
    Returnerar en lista med namnen på alla bevakade sektorer vars
    nyckelord matchar i texten (en text kan höra till flera sektorer).
    """
    if not text:
        return []
    text_lower = text.lower()
    return [
        sector for sector, keywords in WATCHED_SECTORS.items()
        if any(kw in text_lower for kw in keywords)
    ]
