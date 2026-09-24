"""
Kategoriserar malware-familjer (från ThreatFox-data) och mappar dem mot
MITRE ATT&CK-tekniker.

VIKTIG ÄRLIGHET OM PRECISION: att veta exakt vilka tekniker en enskild
malware-familj använder kräver djup verifierad forskning per familj —
det garanteras inte här. Istället klassificeras varje familj i en
GENERELL KATEGORI (stealer, RAT, loader, ransomware, botnet, miner,
backdoor) baserat på namnmönster, och varje kategori kopplas till några
väletablerade, allmänt kända ATT&CK-tekniker för just den kategorin av
skadlig kod. Det är en rimlig approximation för att ge riktning och
gemensamt språk (TTPs snarare än bara malware-namn) — inte en exakt,
verifierad per-familj-attribuering. Ett fåtal mycket kända, väldokumenterade
familjer har egna, mer specifika mappningar (se FAMILY_OVERRIDES).

Referens: https://attack.mitre.org/
"""

import re

# Tekniker per generell kategori. Format: (technique_id, kort namn)
CATEGORY_TECHNIQUES = {
    "Stealer (infostealer)": [
        ("T1555", "Credentials from Password Stores"),
        ("T1005", "Data from Local System"),
        ("T1539", "Steal Web Session Cookie"),
    ],
    "RAT (fjärrstyrning)": [
        ("T1219", "Remote Access Software"),
        ("T1071", "Application Layer Protocol (C2)"),
        ("T1056", "Input Capture"),
    ],
    "Loader / Dropper": [
        ("T1027", "Obfuscated Files or Information"),
        ("T1105", "Ingress Tool Transfer"),
        ("T1055", "Process Injection"),
    ],
    "Ransomware": [
        ("T1486", "Data Encrypted for Impact"),
        ("T1490", "Inhibit System Recovery"),
        ("T1489", "Service Stop"),
    ],
    "Botnet / DDoS": [
        ("T1498", "Network Denial of Service"),
        ("T1110", "Brute Force (standardlösenord)"),
    ],
    "Coinminer": [
        ("T1496", "Resource Hijacking"),
    ],
    "Backdoor": [
        ("T1071", "Application Layer Protocol (C2)"),
        ("T1547", "Boot or Logon Autostart Execution"),
    ],
    "Okategoriserad skadlig kod": [
        ("T1105", "Ingress Tool Transfer"),
        ("T1071", "Application Layer Protocol (C2)"),
    ],
}

# Ett fåtal välkända, väldokumenterade familjer med lite mer specifik mappning.
# Namn i gemener för enkel jämförelse.
FAMILY_OVERRIDES = {
    "wannacryptor": ("Ransomware", [
        ("T1486", "Data Encrypted for Impact"),
        ("T1210", "Exploitation of Remote Services (EternalBlue)"),
        ("T1021", "Remote Services (SMB-spridning)"),
    ]),
    "mirai": ("Botnet / DDoS", [
        ("T1498", "Network Denial of Service"),
        ("T1110", "Brute Force (standard-IoT-lösenord)"),
        ("T1584", "Compromise Infrastructure"),
    ]),
    "blackmatter": ("Ransomware", CATEGORY_TECHNIQUES["Ransomware"]),
    "agent tesla": ("Stealer (infostealer)", [
        ("T1056", "Input Capture (keylogging)"),
        ("T1555", "Credentials from Password Stores"),
        ("T1071", "Application Layer Protocol (C2 via SMTP/FTP)"),
    ]),
    "clearfake": ("Loader / Dropper", [
        ("T1189", "Drive-by Compromise"),
        ("T1204", "User Execution (falsk webbläsaruppdatering)"),
        ("T1036", "Masquerading"),
    ]),
    "vidar": ("Stealer (infostealer)", CATEGORY_TECHNIQUES["Stealer (infostealer)"]),
    "formbook": ("Stealer (infostealer)", CATEGORY_TECHNIQUES["Stealer (infostealer)"]),
    "amos": ("Stealer (infostealer)", [
        ("T1555", "Credentials from Password Stores (macOS Keychain)"),
        ("T1005", "Data from Local System"),
    ]),
    "cobalt strike": ("RAT (fjärrstyrning)", [
        ("T1219", "Remote Access Software"),
        ("T1071", "Application Layer Protocol (C2)"),
        ("T1055", "Process Injection"),
    ]),
    "emotet": ("Loader / Dropper", [
        ("T1566", "Phishing (initial spridningsväg)"),
        ("T1105", "Ingress Tool Transfer"),
        ("T1071", "Application Layer Protocol (C2)"),
    ]),
    "troldesh": ("Ransomware", CATEGORY_TECHNIQUES["Ransomware"]),
    "prometei": ("Botnet / DDoS", [
        ("T1496", "Resource Hijacking (cryptomining)"),
        ("T1071", "Application Layer Protocol (C2)"),
    ]),
    "gcleaner": ("Loader / Dropper", CATEGORY_TECHNIQUES["Loader / Dropper"]),
    "mass logger": ("Stealer (infostealer)", [
        ("T1056", "Input Capture (keylogging)"),
        ("T1555", "Credentials from Password Stores"),
    ]),
}

# Namnmönster -> kategori, kollas i ordning (första träff vinner)
CATEGORY_KEYWORD_RULES = [
    ("stealer", "Stealer (infostealer)"),
    ("stealc", "Stealer (infostealer)"),
    ("rat", "RAT (fjärrstyrning)"),
    ("loader", "Loader / Dropper"),
    ("miner", "Coinminer"),
    ("coinminer", "Coinminer"),
    ("backdoor", "Backdoor"),
    ("ransom", "Ransomware"),
]

# Kända RAT-namn som inte innehåller ordet "rat" som substräng på ett
# pålitligt sätt, eller andra specialfall.
KNOWN_RAT_NAMES = {"njrat", "asyncrat", "xworm", "remcos", "quasar rat", "x-agent", "vshell", "adaptixc2"}


def parse_family_from_value(value: str) -> str | None:
    """
    Plockar ut malware-familjenamnet ur ett ThreatFox-annoterat IOC-värde,
    t.ex. "evil.example  [ClearFake, confidence 100]" -> "ClearFake".
    Returnerar None om värdet inte matchar det mönstret (dvs. inte kommer
    från ThreatFox).
    """
    match = re.search(r"\[([^,\]]+),\s*confidence", value)
    if match:
        return match.group(1).strip()
    return None


def classify_family(family: str):
    """Returnerar (kategori, [(technique_id, namn), ...]) för en malware-familj."""
    key = family.lower().strip()

    if key in FAMILY_OVERRIDES:
        return FAMILY_OVERRIDES[key]

    if key in KNOWN_RAT_NAMES:
        return ("RAT (fjärrstyrning)", CATEGORY_TECHNIQUES["RAT (fjärrstyrning)"])

    for keyword, category in CATEGORY_KEYWORD_RULES:
        if keyword in key:
            return (category, CATEGORY_TECHNIQUES[category])

    return ("Okategoriserad skadlig kod", CATEGORY_TECHNIQUES["Okategoriserad skadlig kod"])
