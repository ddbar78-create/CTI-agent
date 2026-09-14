"""
LLM-baserad kontext-extraktion via Claude API.

Kompletterar regex-extraktionen i extract.py med saker regex aldrig kan
fånga: vilken hotaktör som nämns, vilka TTPs (tactics/techniques) som
beskrivs, vilken sektor som är mål, och en grov allvarlighetsgrad.

Kräver en ANTHROPIC_API_KEY (miljövariabel, sätts som GitHub Secret).
Om nyckeln saknas hoppas LLM-berikningen bara över — resten av agenten
(RSS + regex + ThreatFox) fungerar precis som vanligt utan den.
"""

import os
import sys
import json

import requests

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-haiku-4-5-20251001"

SYSTEM_PROMPT = """Du är en CTI-analytiker. Du får en artikelrubrik och en \
kort sammanfattning från en säkerhetsblogg eller CERT-varning. Extrahera \
strukturerad information.

Svara ENDAST med ett JSON-objekt, inget annat, i exakt detta format:
{
  "is_relevant": true eller false,
  "threat_actor": "namnet på hotaktör/grupp om nämnd, annars null",
  "ttps": ["kort lista med tekniker/taktiker som nämns, t.ex. phishing, RCE, supply chain"],
  "target_sector": "bransch/sektor som är mål, om nämnd, annars null",
  "severity": "low", "medium", "high" eller "critical",
  "one_line_summary": "en mening på svenska som sammanfattar vad som hänt"
}

is_relevant ska vara false om artikeln inte handlar om en konkret \
säkerhetshändelse, sårbarhet eller hotaktör (t.ex. allmän nyhet, \
produktlansering eller opinion)."""


def enrich_article(title: str, summary: str) -> dict | None:
    """
    Skickar en artikel till Claude för strukturerad analys.
    Returnerar en dict enligt SYSTEM_PROMPT, eller None om nyckel saknas
    eller något gick fel (loggat till stderr, men stoppar aldrig agenten).
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None

    user_content = f"Rubrik: {title}\n\nSammanfattning: {summary[:2000]}"

    try:
        resp = requests.post(
            ANTHROPIC_API_URL,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": MODEL,
                "max_tokens": 400,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": user_content}],
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        print(f"    LLM-anrop misslyckades: {e}", file=sys.stderr)
        return None

    text_blocks = [
        block.get("text", "")
        for block in data.get("content", [])
        if block.get("type") == "text"
    ]
    raw_text = "".join(text_blocks).strip()

    raw_text = raw_text.replace("```json", "").replace("```", "").strip()

    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        print(f"    Kunde inte tolka LLM-svar som JSON: {raw_text[:200]}",
              file=sys.stderr)
        return None

    return parsed


if __name__ == "__main__":
    result = enrich_article(
        title="New APT41 campaign targets healthcare sector via phishing",
        summary=("Researchers observed APT41 using spear-phishing emails "
                  "to deliver a custom RAT against hospital IT networks."),
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
