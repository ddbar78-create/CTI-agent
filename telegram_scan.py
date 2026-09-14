"""
Hämtar de senaste inläggen från PUBLIKA Telegram-kanaler via t.me:s
webbförhandsvisning (https://t.me/s/<kanal>) — kräver ingen Telegram-API-
nyckel, ingen telefoninloggning, inga hemligheter alls.

Begränsning: fungerar bara för publika kanaler. Privata grupper eller
kanaler som kräver inbjudan syns inte här (och ska inte skrapas —
se telegram_channels.py för riktlinjer om ansvarsfull användning).
"""

import sys

import requests
from bs4 import BeautifulSoup

from storage import get_conn, save_article, save_iocs
from extract import extract_iocs

TELEGRAM_WEB_BASE = "https://t.me/s/"


def fetch_channel_messages(channel: str, limit: int = 20) -> list:
    """Hämtar de senaste inläggen från en publik Telegram-kanal."""
    url = f"{TELEGRAM_WEB_BASE}{channel}"
    try:
        resp = requests.get(
            url, timeout=20, headers={"User-Agent": "Mozilla/5.0"}
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"    Fel vid hämtning av Telegram-kanal @{channel}: {e}",
              file=sys.stderr)
        return []

    if "tgme_widget_message" not in resp.text:
        print(f"    Kanalen '@{channel}' verkar inte finnas eller är inte publik.",
              file=sys.stderr)
        return []

    soup = BeautifulSoup(resp.text, "html.parser")
    messages = []

    for msg_div in soup.select(".tgme_widget_message")[-limit:]:
        text_div = msg_div.select_one(".tgme_widget_message_text")
        text = text_div.get_text("\n").strip() if text_div else ""
        if not text:
            continue  # hoppa över rena bild-/videoinlägg utan text

        link_tag = msg_div.select_one("a.tgme_widget_message_date")
        link = link_tag["href"] if link_tag and link_tag.has_attr("href") else url

        time_tag = msg_div.select_one("time")
        published = time_tag["datetime"] if time_tag and time_tag.has_attr("datetime") else ""

        messages.append({"text": text, "link": link, "published": published})

    return messages


def run_telegram(channels: list) -> int:
    """Hämtar och lagrar nya inlägg från alla kanaler i listan. Returnerar antal nya inlägg."""
    if not channels:
        return 0

    total_new = 0
    total_iocs = 0
    with get_conn() as conn:
        for channel in channels:
            print(f"[+] Hämtar: Telegram @{channel} ...")
            messages = fetch_channel_messages(channel)

            for msg in messages:
                title = msg["text"][:100].replace("\n", " ")
                article_id = save_article(
                    conn,
                    feed=f"Telegram @{channel}",
                    title=title,
                    link=msg["link"],
                    published=msg["published"],
                    summary=msg["text"],
                )
                if article_id is None:
                    continue  # redan sedd tidigare

                total_new += 1

                iocs = extract_iocs(msg["text"])
                if iocs:
                    save_iocs(conn, article_id, iocs)
                    count = sum(len(v) for v in iocs.values())
                    total_iocs += count
                    print(f"    Nytt inlägg: {title}  ({count} IOCs)")

    if total_new:
        print(f"    Telegram: {total_new} nya inlägg, {total_iocs} nya IOCs")
    else:
        print("    Telegram: inga nya inlägg.")

    return total_new


if __name__ == "__main__":
    from telegram_channels import CHANNELS
    run_telegram(CHANNELS)
