"""
Din teknikbevakning — vilka produkter/system du vill hålla koll på.

Agenten matchar sedan nya aktivt utnyttjade sårbarheter (CISA KEV), CVE:er
och artiklar mot dina nyckelord och visar träffarna i dashboarden
(sektionen 'Teknikbevakning').

Listan nedan är förifylld med produkter som ofta utnyttjas i angrepp, så att
du ser resultat direkt. ÄNDRA den till det du faktiskt använder:
  - "name":     visningsnamn i dashboarden
  - "keywords": ord/fraser som ska matcha (skiftlägesokänsligt, hela ord).
                Var specifik — "asa" ensamt skulle matcha fel saker, använd
                hellre "cisco asa". Ta bort rader du inte vill ha.
"""

TECH_WATCHLIST = [
    {"name": "Fortinet (FortiGate/FortiOS m.fl.)",
     "keywords": ["fortinet", "fortigate", "fortios", "fortimanager", "fortiweb", "fortisiem", "forticlient"]},
    {"name": "Citrix NetScaler / ADC / Gateway",
     "keywords": ["citrix", "netscaler"]},
    {"name": "Microsoft Exchange",
     "keywords": ["exchange server", "microsoft exchange", "proxyshell", "proxylogon"]},
    {"name": "Microsoft SharePoint",
     "keywords": ["sharepoint"]},
    {"name": "Ivanti (Connect Secure / EPMM / m.fl.)",
     "keywords": ["ivanti", "pulse secure", "connect secure"]},
    {"name": "Palo Alto Networks (PAN-OS / GlobalProtect)",
     "keywords": ["pan-os", "globalprotect", "palo alto networks"]},
    {"name": "Cisco (ASA / Firepower / IOS XE)",
     "keywords": ["cisco asa", "cisco ios xe", "cisco firepower", "cisco secure firewall",
                  "adaptive security appliance", "cisco ftd"]},
    {"name": "VMware (ESXi / vCenter)",
     "keywords": ["esxi", "vcenter", "vmware"]},
    {"name": "Veeam",
     "keywords": ["veeam"]},
    {"name": "Atlassian (Confluence / Jira)",
     "keywords": ["confluence", "atlassian", "jira"]},
    {"name": "SonicWall",
     "keywords": ["sonicwall"]},
    {"name": "Check Point",
     "keywords": ["check point", "checkpoint"]},
]
