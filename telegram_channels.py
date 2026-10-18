"""
Lista över PUBLIKA Telegram-kanaler att bevaka.
Ange bara kanalens användarnamn, utan @ och utan full URL,
t.ex. "vxunderground" (inte "https://t.me/vxunderground").

VIKTIGT — använd ansvarsfullt:
Lägg bara till publika kanaler du har legitim rätt att läsa och som är
relevanta för legitimt CTI-arbete (forskarkanaler, malware-analys,
breach-nyheter, CERT-varningar). Använd inte detta för att samla in
innehåll från kanaler som distribuerar stöldgods, olagligt material,
eller kräver medlemskap/inbjudan — verktyget stödjer bara publika kanaler
och är inte byggt eller avsett för något annat.
"""

CHANNELS = [
    # Forskare och malware-analys
    "vxunderground",

    # Hacktivistgrupper som utför DDoS (följs för att se vilka mål och länder de pekar ut).
    # Källa: deepdarkCTI (github.com/fastfire/deepdarkCTI), status ONLINE 2026-10-18.
    # Kontrollera att kanalen fortfarande är den riktiga innan du behåller den, kopior förekommer.
    "nnm05716english",   # NoName057(16), engelska kanalen
    "KILLNETddos",       # Killnet
    "KillNetSyndicate",  # Killnet Syndicate
    "usersecc",          # UserSec
    "DIeNlt",            # DieNet
    "dienet1",           # DieNet
    "dienet3",           # DieNet
]
