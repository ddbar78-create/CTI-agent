"""
Notiser — skickar larm från intel.py (avvikelser, nordiska offer i din sektor, KEV som berör din teknik)
till de kanaler du har ställt in. Alla kanaler är valfria och styrs av GitHub-secrets (Settings,
Secrets and variables, Actions). Lämnas alla tomma skickas ingenting.

  DISCORD_WEBHOOK_URL   Discord: Serverinställningar, Integrationer, Webhooks, Ny webhook
  TEAMS_WEBHOOK_URL     Microsoft Teams: kanal, Workflows/Incoming Webhook
  NTFY_TOPIC            Push till mobilen via ntfy.sh (gratis): välj ett långt, hemligt ämnesnamn
                        och prenumerera på det i appen ntfy. (NTFY_SERVER om du kör egen server)
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_TO   Mejl (t.ex. Gmail med applösenord:
                        smtp.gmail.com, 587)
  TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID   Telegram-bot (gratis, officiellt API): skapa en bot med @BotFather,
                        skriv till den och hämta chat-id. Fungerar som push i mobilen.
  ELKS_USER, ELKS_PASS, SMS_TO (och valfritt SMS_FROM)   SMS via 46elks (betalt per SMS). SMS_TO i
                        formatet +46701234567. Skickar bara nivå Kritisk, för att hålla kostnaden nere.

Signal stöds inte: Signal saknar officiellt API för bottar och kan inte köras stabilt från GitHub Actions.
Använd Telegram eller ntfy som push, eller SMS.

Samma larm skickas aldrig två gånger (tabellen alerts_sent). Max 15 larm per körning och kanal, och
bara Kritisk/Hög skickas som standard (ändra MIN_LEVEL nedan).

Repot är publikt: lägg ALDRIG webhook-adresser eller lösenord i koden, bara i secrets.
"""

import json
import os
import smtplib
import sqlite3
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests

from intel import LEVEL_ORDER, compute_alerts
from storage import DB_PATH

MIN_LEVEL = "Hög"     # lägsta nivå som skickas: Kritisk, Hög, Medel eller Info
MAX_PER_RUN = 15
PANEL_URL = os.environ.get("PANEL_URL", "https://ddbar78-create.github.io/CTI-agent/")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts_sent (
    key TEXT PRIMARY KEY,
    sent_at TEXT DEFAULT CURRENT_TIMESTAMP
)
"""


def _format(alerts) -> tuple:
    subject = f"CTI: {len(alerts)} nya larm"
    icons = {"Kritisk": "🔴", "Hög": "🟠", "Medel": "🟡", "Info": "🔵"}
    lines = [f"{icons.get(a['level'], '•')} [{a['level']}] {a['title']}\n    {a['detail']}" for a in alerts]
    return subject, "\n".join(lines) + f"\n\nPanel: {PANEL_URL}"


def _send_discord(url, subject, body):
    requests.post(url, json={"content": (f"**{subject}**\n{body}")[:1900]}, timeout=20).raise_for_status()


def _send_teams(url, subject, body):
    requests.post(url, json={"text": f"**{subject}**\n\n" + body.replace("\n", "\n\n")}, timeout=20).raise_for_status()


def _send_ntfy(topic, subject, body):
    server = os.environ.get("NTFY_SERVER", "https://ntfy.sh").rstrip("/")
    requests.post(f"{server}/{topic}", data=body.encode("utf-8"),
                  headers={"Title": subject.encode("utf-8"), "Priority": "high", "Tags": "warning"}, timeout=20).raise_for_status()


def mail_configured() -> bool:
    return all(os.environ.get(k) for k in ("SMTP_HOST", "SMTP_USER", "SMTP_PASS", "MAIL_TO"))


def send_mail(subject, body, html_body=None):
    """Skickar mejl (text, och HTML om html_body anges) via SMTP-secrets."""
    host, user, pw, to = (os.environ.get(k, "") for k in ("SMTP_HOST", "SMTP_USER", "SMTP_PASS", "MAIL_TO"))
    port = int(os.environ.get("SMTP_PORT", "587") or 587)
    if html_body:
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))
    else:
        msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"], msg["From"], msg["To"] = subject, user, to
    with smtplib.SMTP(host, port, timeout=30) as s:
        s.starttls()
        s.login(user, pw)
        s.sendmail(user, [t.strip() for t in to.split(",")], msg.as_string())


def _send_mail(subject, body):
    send_mail(subject, body)


def _send_telegram(subject, body):
    url = f"https://api.telegram.org/bot{os.environ['TELEGRAM_BOT_TOKEN']}/sendMessage"
    requests.post(url, json={"chat_id": os.environ["TELEGRAM_CHAT_ID"], "text": (subject + "\n" + body)[:4000],
                             "disable_web_page_preview": True}, timeout=20).raise_for_status()


def _send_sms(subject, body):
    """SMS via 46elks. Bara en kort text (högst ca 450 tecken = 3 SMS)."""
    text = (subject + ": " + body.split("\n\nPanel:")[0].replace("\n    ", " - ").replace("\n", " "))[:450]
    sender = os.environ.get("SMS_FROM", "CTI")[:11]
    requests.post("https://api.46elks.com/a1/sms", auth=(os.environ["ELKS_USER"], os.environ["ELKS_PASS"]),
                  data={"from": sender, "to": os.environ["SMS_TO"], "message": text}, timeout=20).raise_for_status()


def _channels() -> list:
    ch = []
    if os.environ.get("DISCORD_WEBHOOK_URL"):
        ch.append(("Discord", lambda s, b: _send_discord(os.environ["DISCORD_WEBHOOK_URL"], s, b)))
    if os.environ.get("TEAMS_WEBHOOK_URL"):
        ch.append(("Teams", lambda s, b: _send_teams(os.environ["TEAMS_WEBHOOK_URL"], s, b)))
    if os.environ.get("NTFY_TOPIC"):
        ch.append(("ntfy", lambda s, b: _send_ntfy(os.environ["NTFY_TOPIC"], s, b)))
    if mail_configured():
        ch.append(("Mejl", _send_mail))
    if os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID"):
        ch.append(("Telegram", _send_telegram))
    if all(os.environ.get(k) for k in ("ELKS_USER", "ELKS_PASS", "SMS_TO")):
        ch.append(("SMS", _send_sms, "Kritisk"))
    return ch


def run_alerts(db_path: str = DB_PATH) -> int:
    """Skickar nya larm. Returnerar antal skickade larm (0 om inga kanaler är inställda)."""
    channels = _channels()
    if not channels:
        print("[+] Notiser: inga kanaler inställda (se notifier.py), hoppar över.")
        return 0

    alerts = [a for a in compute_alerts(db_path) if LEVEL_ORDER.get(a["level"], 9) <= LEVEL_ORDER[MIN_LEVEL]]
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute(_SCHEMA)
    sent = {r[0] for r in conn.execute("SELECT key FROM alerts_sent")}
    new = [a for a in alerts if a["key"] not in sent][:MAX_PER_RUN]
    if not new:
        conn.close()
        print("[+] Notiser: inga nya larm.")
        return 0

    delivered = 0
    for ch in channels:
        name, fn = ch[0], ch[1]
        subset = [a for a in new if len(ch) < 3 or LEVEL_ORDER.get(a["level"], 9) <= LEVEL_ORDER[ch[2]]]
        if not subset:
            delivered += 1  # inget att skicka på denna kanal räknas som lyckat
            continue
        subject, body = _format(subset)
        try:
            fn(subject, body)
            delivered += 1
        except Exception as e:  # en trasig kanal ska inte stoppa de andra
            print(f"    Notiser: {name} misslyckades ({type(e).__name__}: {str(e)[:120]})", file=sys.stderr)
    if delivered:  # markera som skickade bara om minst en kanal lyckades
        conn.executemany("INSERT OR IGNORE INTO alerts_sent (key) VALUES (?)", [(a["key"],) for a in new])
        conn.execute("DELETE FROM alerts_sent WHERE sent_at < datetime('now', '-60 days')")
        conn.commit()
    conn.close()
    print(f"[+] Notiser: {len(new)} larm skickade via {delivered} av {len(channels)} kanaler.")
    if not delivered:
        raise RuntimeError("alla notiskanaler misslyckades")
    return len(new) if delivered else 0


if __name__ == "__main__":
    run_alerts()
