"""
Bevakningslista — ange organisationer/domäner du vill hålla koll på (din
kommun, ett transportbolag, din arbetsgivare ...) och få träff i ALLA
insamlade källor. Träffar sparas permanent (tabellen watchlist_hits) och
rensas aldrig, så en träff försvinner inte när ThreatFox-posten den
kom från rensas efter 7 dagar.

REDIGERA WATCHLIST NEDAN. Varje post har:
  name     Visningsnamn på dashboarden.
  terms    Namn/fraser att söka efter i text (artiklar, Telegram, offernamn).
           Matchas som hela ord, skiftlägesokänsligt. Böjningar som
           "Trafikverkets" fångas.
  domains  Organisationens OFFICIELLA domäner (utan https://). Används för:
             - träff om domänen (eller en underdomän) listas som IOC, dvs.
               den kan vara komprometterad eller missbrukad
             - träff om domänen nämns i text
             - att hitta IMITATIONSDOMÄNER: domäner i IOC-data som innehåller
               organisationens varumärke men inte är den officiella domänen
               (t.ex. "trafikverket-login.top" när du bevakar trafikverket.se)
  brands   (valfritt) Extra varumärkesord för imitationsjakt, minst 4 tecken.
           Som standard används domännamnets första del (om minst 5 tecken).

TRÄFFTYPER:
  ioc_domain  Bevakad domän finns i IOC-data           (allvarligast)
  ransomware  Organisationen finns bland ransomware-offer
  lookalike   Möjlig imitationsdomän
  article     Omnämnd i artikel/Telegram
"""

import re
from urllib.parse import urlparse

WATCHLIST = [
    # Platshållare — ändra eller ta bort. Exemplen nedan är utkommenterade;
    # KONTROLLERA domänerna själv innan du använder dem.
    {
        "name": "Exempelkommun (ändra mig)",
        "terms": ["Exempelkommun"],
        "domains": ["exempelkommun.example"],
    },
    # {
    #     "name": "Trafikverket",
    #     "terms": ["Trafikverket"],
    #     "domains": ["trafikverket.se"],
    # },
    # {
    #     "name": "PostNord",
    #     "terms": ["PostNord"],
    #     "domains": ["postnord.com", "postnord.se"],
    # },
]

MIN_AUTO_BRAND_LENGTH = 5
MIN_EXPLICIT_BRAND_LENGTH = 4


def _term_regex(terms: list):
    """Hela ord, skiftlägesokänsligt, tillåter avslutande böjning (s, 's)."""
    cleaned = [t.strip() for t in terms if t and t.strip()]
    if not cleaned:
        return None
    alternatives = "|".join(re.escape(t) for t in cleaned)
    return re.compile(r"\b(?:" + alternatives + r")(?:s|'s|’s)?\b", re.IGNORECASE)


def _normalize_domain(value: str) -> str:
    """Rensar ThreatFox-annotering och 'defanging' och returnerar en ren domän."""
    v = (value or "").split(" [")[0].strip().lower()
    v = v.replace("[.]", ".").replace("(.)", ".")
    return v.strip(".")


def _host_from_ioc(ioc_type: str, value: str) -> str:
    """Plockar ut värdnamnet ur ett domän- eller URL-IOC ('' om det inte går)."""
    v = (value or "").split(" [")[0].strip()
    if ioc_type == "domain":
        return _normalize_domain(v)
    v = v.replace("hxxp", "http").replace("[.]", ".").replace("(.)", ".")
    try:
        host = urlparse(v).hostname or ""
    except ValueError:
        return ""
    return host.lower().strip(".")


def _is_official(host: str, official_domains: list) -> bool:
    return any(host == d or host.endswith("." + d) for d in official_domains)


def _brand_tokens(entry: dict) -> list:
    tokens = set()
    for d in entry.get("domains", []):
        parts = d.lower().strip(".").split(".")
        if len(parts) >= 2 and len(parts[-2]) >= MIN_AUTO_BRAND_LENGTH:
            tokens.add(parts[-2])
    for b in entry.get("brands", []):
        b = b.strip().lower()
        if len(b) >= MIN_EXPLICIT_BRAND_LENGTH:
            tokens.add(b)
    return sorted(tokens)


def _prepare(watchlist: list) -> list:
    prepared = []
    for entry in watchlist:
        domains = [d.lower().strip(".") for d in entry.get("domains", []) if d]
        prepared.append({
            "name": entry["name"],
            "domains": domains,
            "text_regex": _term_regex(list(entry.get("terms", [])) + domains),
            "brand_tokens": _brand_tokens(entry),
        })
    return prepared


def find_hits(victims: list, articles: list, ioc_rows: list, watchlist: list = None) -> list:
    """
    Ren funktion (ingen databas) som returnerar alla träffar som en lista av
    dicts: {entry, kind, detail, source, link, ref}.

    victims:  [{group_name, victim, country, ...}]
    articles: [{title, link, feed, summary, full_text}]
    ioc_rows: [{ioc_type, value, feed, link}]  (bara 'domain' och 'url' används)
    """
    hits = []
    for e in _prepare(WATCHLIST if watchlist is None else watchlist):
        rx = e["text_regex"]

        for v in victims:
            if rx and rx.search(v.get("victim") or ""):
                hits.append({
                    "entry": e["name"], "kind": "ransomware",
                    "detail": f'{v["victim"]} ({v.get("country") or "?"})',
                    "source": f'ransomware.live · {v.get("group_name") or "okänd grupp"}',
                    "link": "",
                    "ref": f'{v.get("group_name")}|{v.get("victim")}|{v.get("attack_date")}',
                })

        for a in articles:
            text = f'{a.get("title") or ""} {a.get("summary") or ""} {(a.get("full_text") or "")[:3000]}'
            if rx and rx.search(text):
                hits.append({
                    "entry": e["name"], "kind": "article",
                    "detail": a.get("title") or "(utan titel)",
                    "source": a.get("feed") or "",
                    "link": a.get("link") or "", "ref": a.get("link") or a.get("title") or "",
                })

        for r in ioc_rows:
            if r.get("ioc_type") not in ("domain", "url"):
                continue
            host = _host_from_ioc(r["ioc_type"], r["value"])
            if not host:
                continue
            shown = (r["value"] or "").split(" [")[0].strip()
            if _is_official(host, e["domains"]):
                hits.append({
                    "entry": e["name"], "kind": "ioc_domain",
                    "detail": f'{shown} listas som IOC',
                    "source": r.get("feed") or "", "link": r.get("link") or "",
                    "ref": f'{r["ioc_type"]}|{shown}',
                })
            elif any(tok in host for tok in e["brand_tokens"]):
                hits.append({
                    "entry": e["name"], "kind": "lookalike",
                    "detail": f'{host} innehåller varumärket',
                    "source": r.get("feed") or "", "link": r.get("link") or "",
                    "ref": f'{r["ioc_type"]}|{host}',
                })
    return hits


def run_watchlist_scan() -> list:
    """
    Skannar databasen, sparar träffar permanent och returnerar de NYA
    träffarna (används för notiser). Anropas av agent.py varje körning,
    FÖRE rensningen av gamla poster.
    """
    from storage import get_conn, save_watchlist_hit

    if not WATCHLIST:
        return []

    print("[+] Bevakningslista: skannar alla källor ...")
    with get_conn() as conn:
        cur = conn.cursor()

        cur.execute("SELECT group_name, victim, country, attack_date FROM ransomware_victims")
        victims = [dict(zip(("group_name", "victim", "country", "attack_date"), r))
                   for r in cur.fetchall()]

        cur.execute(
            """
            SELECT title, link, feed, summary, full_text FROM articles
            WHERE feed != 'ransomware.live' AND feed NOT LIKE 'ThreatFox%'
            ORDER BY id DESC LIMIT 500
            """
        )
        articles = [dict(zip(("title", "link", "feed", "summary", "full_text"), r))
                    for r in cur.fetchall()]

        cur.execute(
            """
            SELECT iocs.ioc_type, iocs.value, articles.feed, articles.link
            FROM iocs JOIN articles ON articles.id = iocs.article_id
            WHERE iocs.ioc_type IN ('domain', 'url')
            """
        )
        ioc_rows = [dict(zip(("ioc_type", "value", "feed", "link"), r))
                    for r in cur.fetchall()]

        new_hits = []
        for h in find_hits(victims, articles, ioc_rows):
            if save_watchlist_hit(conn, h["entry"], h["kind"], h["detail"],
                                  h["source"], h["link"], h["ref"]):
                new_hits.append(h)

    if new_hits:
        print(f"    Bevakningslista: {len(new_hits)} NYA träffar")
        for h in new_hits[:10]:
            print(f"      [{h['kind']}] {h['entry']}: {h['detail']}")
    else:
        print("    Bevakningslista: inga nya träffar.")
    return new_hits


if __name__ == "__main__":
    run_watchlist_scan()
