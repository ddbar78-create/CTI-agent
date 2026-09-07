
"""
Extraherar Indicators of Compromise (IOCs) ur fri text med regex.
"""

import re

PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    ),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:[a-zA-Z]{2,})\b"
    ),
    "url": re.compile(r"\bhxxps?://[^\s\"'<>]+|\bhttps?://[^\s\"'<>]+"),
}

DOMAIN_NOISE = {
    "feedburner.com", "www.w3.org", "creativecommons.org", "schema.org",
    "wordpress.com", "wp.com", "example.com",
}


def extract_iocs(text: str) -> dict:
    """Returnerar en dict {typ: set(värden)} med unika IOCs ur texten."""
    if not text:
        return {}

    results = {}
    for ioc_type, pattern in PATTERNS.items():
        matches = set(pattern.findall(text))
        if ioc_type == "domain":
            matches = {m for m in matches if m.lower() not in DOMAIN_NOISE}
        if matches:
            results[ioc_type] = matches
    return results


if __name__ == "__main__":
    sample = """
    The malware communicated with 185.220.101.5 and used the domain
    evil-c2-panel.ru. Payload hash: 44d88612fea8a8f36de82e1278abb02f.
    Related to CVE-2024-3400. See https://example.com/report for details.
    """
    for ioc_type, values in extract_iocs(sample).items():
        print(f"{ioc_type}: {values}")
