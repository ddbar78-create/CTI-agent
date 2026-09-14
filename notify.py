"""
Skickar en sammanfattande notis efter varje körning — men bara om det
faktiskt finns något värt att flagga. Annars hade du fått en ping varje
timme i evighet, vilket snabbt blir brus ingen läser.

Stöder två oberoende kanaler, båda valfria:
  - Slack: sätt SLACK_WEBHOOK_URL (Incoming Webhook-URL, gratis att skapa
    i valfri Slack-arbetsyta under "Apps -> Incoming Webhooks")
  - E-post: sätt SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, EMAIL_TO
    (fungerar med Gmail, Outlook, eller valfri SMTP-leverantör)

Saknas båda hoppar notifieringen bara tyst över — resten av agenten
påverkas inte.
"""

import os
import smtplib
import sys
from email.mime.text import MIMEText

import requests


def send_slack(text: str):
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        return

    try:
        resp = requests.post(webhook_url, json={"text": text}, timeout=15)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"    Slack-notis misslyckades: {e}", file=sys.stderr)


def send_email(subject: str, body: str):
    host = os.environ.get("SMTP_HOST")
    port = os.environ.get("SMTP_PORT")
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASS")
    to_addr = os.environ.get("EMAIL_TO")

    if not all([host, port, user, password, to_addr]):
        return

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = to_addr

    try:
        with smtplib.SMTP(host, int(port), timeout=20) as server:
            server.starttls()
            server.login(user, password)
            server.sendmail(user, [to_addr], msg.as_string())
    except Exception as e:
        print(f"    E-postnotis misslyckades: {e}", file=sys.stderr)


def notify(summary_lines: list):
    """
    Tar en lista med textrader (redan formaterade) och skickar dem som en
    enda sammanfattande notis till alla konfigurerade kanaler.
    """
    if not summary_lines:
        return

    text = "*CTI-agent — nya fynd*\n" + "\n".join(summary_lines)
    send_slack(text)
    send_email("CTI-agent: nya fynd", "\n".join(summary_lines))
