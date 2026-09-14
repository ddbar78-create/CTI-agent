"""
Hämtar den fullständiga artikeltexten för nya RSS-artiklar (inte bara det
ofta kraftigt förkortade RSS-utdraget), och följer sedan UTVALDA
referenslänkar i artikeln till kända sårbarhets-/leverantörskällor —
NVD, CVE.org, GitHub Advisories, Microsoft MSRC, CISA — för ännu mer
detaljerad kontext.

Detta är medvetet AVGRÄNSAT: vi crawlar inte godtyckliga externa länkar
(reklam, sociala medier, andra nyhetssidor) — bara referenser till kända,
relevanta säkerhetskällor. Målet är djupare kontext per artikel, inte en
allmän webcrawler.

Respekterar robots.txt för varje domän som besöks, och håller en
trafikvänlig paus mellan anrop.
"""

import sys
import time
import urllib.robotparser
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

MAX_CRAWLS_PER_RUN = 40
MAX_FOLLOWED_LINKS_PER_ARTICLE = 3
REQUEST_TIMEOUT = 15
DELAY_BETWEEN_REQUESTS = 1.0
USER_AGENT = "cti-agent/1.0 (+personal research bot; respects robots.txt)"

# Vi följer bara länkar till DESSA domäner för fördjupning — inte
# godtyckliga externa länkar i artikeln.
REFERENCE_DOMAINS = [
    "nvd.nist.gov",
    "cve.org",
    "github.com/advisories",
    "msrc.microsoft.com",
    "portal.msrc.microsoft.com",
    "exploit-db.com",
    "cisa.gov",
]

_robots_cache: dict = {}


def _allowed_by_robots(url: str) -> bool:
    """Kollar robots.txt för domänen. Vid osäkerhet (kan inte läsas) -> tillåt."""
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    if base not in _robots_cache:
        rp = urllib.robotparser.RobotFileParser()
        rp.set_url(urljoin(base, "/robots.txt"))
        try:
            rp.read()
            _robots_cache[base] = rp
        except Exception:
            _robots_cache[base] = None  # kunde inte läsas — anta tillåtet

    rp = _robots_cache[base]
    if rp is None:
        return True
    return rp.can_fetch(USER_AGENT, url)


def _extract_main_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    main = soup.find("article") or soup.find("main") or soup.body
    if not main:
        return ""
    return main.get_text("\n", strip=True)[:8000]


def _extract_reference_links(html: str, base_url: str) -> list:
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for a in soup.find_all("a", href=True):
        href = urljoin(base_url, a["href"])
        if any(domain in href for domain in REFERENCE_DOMAINS):
            links.append(href)
    return list(dict.fromkeys(links))[:MAX_FOLLOWED_LINKS_PER_ARTICLE]


def crawl_article(url: str) -> str:
    """
    Hämtar fullständig artikeltext plus text från utvalda referenslänkar.
    Returnerar en sammanslagen textsträng (tom vid fel eller robots-blockering).
    """
    if not _allowed_by_robots(url):
        print(f"      robots.txt blockerar crawling av {url}", file=sys.stderr)
        return ""

    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"      Kunde inte crawla {url}: {e}", file=sys.stderr)
        return ""

    article_text = _extract_main_text(resp.text)
    if not article_text:
        print(f"      Ingen huvudtext hittades på {url} (oväntad sidstruktur)", file=sys.stderr)
        return ""

    combined = [article_text]

    for ref_url in _extract_reference_links(resp.text, url):
        time.sleep(DELAY_BETWEEN_REQUESTS)
        if not _allowed_by_robots(ref_url):
            continue
        try:
            ref_resp = requests.get(
                ref_url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT}
            )
            ref_resp.raise_for_status()
        except requests.RequestException:
            continue
        ref_text = _extract_main_text(ref_resp.text)
        if ref_text:
            combined.append(f"[Referens: {ref_url}]\n{ref_text[:3000]}")

    result = "\n\n".join(combined)
    print(f"      Crawlade {url} ({len(result)} tecken hämtade)")
    return result


if __name__ == "__main__":
    text = crawl_article("https://www.bleepingcomputer.com/")
    print(text[:1000])
