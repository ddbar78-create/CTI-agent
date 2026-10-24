"""
Hunting-frågor och ATT&CK Navigator-export.

Genererar färdiga frågor som ditt SOC kan klistra in i sina egna verktyg. Agenten ser aldrig din
interna miljö och kör aldrig frågorna själv. Frågorna är startpunkter: kontrollera tabell- och
fältnamn mot din miljö innan du litar på resultatet.

Plattformar: Microsoft Defender/Sentinel (KQL), Splunk (SPL) och Elastic (KQL).
Tre sorters frågor:
  1. IOC-träffar: aktiva indikatorer med poäng >= 70 (se ioc_confidence.py), max 200 värden per fråga
  2. Beteendefrågor per ATT&CK-teknik (de som observerats bland dina familjer visas först)
  3. Sårbarhetsfrågor för nya aktivt utnyttjade CVE:er (CISA KEV, senaste 14 dagarna)

Navigator-lager (JSON, för https://mitre-attack.github.io/attack-navigator/): tekniker från familjerna
bakom dina IOC:er, poängsatta efter antal indikatorer. Två lager: alla och senaste 30 dagarna.
"""

import html
import json
import re
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone

from ioc_confidence import active_iocs
from storage import DB_PATH

try:
    from attack_mapping import classify_family
except Exception:  # pragma: no cover
    classify_family = None

MAX_VALUES = 200


def _q(value: str) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _list(values, sep=", "):
    return sep.join(_q(v) for v in values)


# ------------------------------------------------------------------ IOC-frågor
def _ioc_sets(db_path):
    rows = active_iocs(db_path, min_score=70, limit=2000)
    ips, domains, urls, sha256 = [], [], [], []
    for r in rows:
        v = r["value"]
        if r["type"] in ("ipv4", "ip:port"):
            ips.append(v.split(":")[0])
        elif r["type"] == "domain":
            domains.append(v.lower())
        elif r["type"] == "url":
            urls.append(v)
        elif r["type"] == "sha256_hash":
            sha256.append(v.lower())
    uniq = lambda xs: list(dict.fromkeys(xs))[:MAX_VALUES]
    return uniq(ips), uniq(domains), uniq(urls), uniq(sha256)


def build_ioc_queries(db_path: str = DB_PATH) -> list:
    ips, domains, urls, sha = _ioc_sets(db_path)
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out = []
    if ips:
        out.append({"title": f"IP-adresser ({len(ips)} st)", "kql":
            f"// CTI-agent {day}: aktiva IP-indikatorer, poäng >= 70\nlet iocIPs = dynamic([{_list(ips)}]);\n"
            "DeviceNetworkEvents\n| where Timestamp > ago(30d)\n| where RemoteIP in (iocIPs)\n"
            "| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine\n| order by Timestamp desc",
            "spl": f"index=* earliest=-30d (dest_ip IN ({_list(ips)}) OR dest IN ({_list(ips)}))\n| stats count min(_time) as first max(_time) as last by src, dest_ip, dest_port\n| convert ctime(first) ctime(last)",
            "elastic": f"destination.ip : ({_list(ips, ' or ')})"})
    if domains:
        out.append({"title": f"Domäner ({len(domains)} st)", "kql":
            f"// CTI-agent {day}: aktiva domän-indikatorer, poäng >= 70\nlet iocDomains = dynamic([{_list(domains)}]);\n"
            "union isfuzzy=true\n(DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteUrl has_any (iocDomains) | project Timestamp, DeviceName, RemoteUrl),\n"
            "(DnsEvents | where TimeGenerated > ago(30d) | where Name has_any (iocDomains) | project Timestamp = TimeGenerated, Computer, Name)",
            "spl": f"index=* earliest=-30d (query IN ({_list(domains)}) OR url_domain IN ({_list(domains)}) OR dest_host IN ({_list(domains)}))\n| stats count by src, query, url_domain",
            "elastic": f"dns.question.name : ({_list(domains, ' or ')}) or url.domain : ({_list(domains, ' or ')})"})
    if urls:
        out.append({"title": f"URL:er ({len(urls)} st)", "kql":
            f"// CTI-agent {day}: aktiva URL-indikatorer\nlet iocUrls = dynamic([{_list(urls)}]);\n"
            "DeviceNetworkEvents\n| where Timestamp > ago(30d)\n| where RemoteUrl in~ (iocUrls)\n| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName",
            "spl": f"index=* earliest=-30d url IN ({_list(urls)})\n| stats count by src, url",
            "elastic": f"url.full : ({_list(urls, ' or ')})"})
    if sha:
        out.append({"title": f"SHA-256-hashar ({len(sha)} st)", "kql":
            f"// CTI-agent {day}: aktiva hash-indikatorer\nlet iocHashes = dynamic([{_list(sha)}]);\n"
            "DeviceFileEvents\n| where Timestamp > ago(30d)\n| where SHA256 in~ (iocHashes)\n| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName",
            "spl": f"index=* earliest=-30d (file_hash IN ({_list(sha)}) OR SHA256 IN ({_list(sha)}) OR Hashes IN ({_list(sha)}))\n| stats count by host, file_name, file_hash",
            "elastic": f"file.hash.sha256 : ({_list(sha, ' or ')}) or process.hash.sha256 : ({_list(sha, ' or ')})"})
    return out


# ------------------------------------------------------------------ beteendefrågor per teknik
TECHNIQUES = {
    "T1059": {"name": "Command and Scripting Interpreter", "kql":
        "DeviceProcessEvents\n| where Timestamp > ago(7d)\n| where FileName in~ (\"powershell.exe\", \"pwsh.exe\")\n"
        "| where ProcessCommandLine has_any (\"-enc\", \"-EncodedCommand\", \"FromBase64String\", \"DownloadString\", \"IEX\")\n"
        "| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName",
        "spl": "index=* sourcetype=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1 earliest=-7d\n"
        "(Image=\"*\\\\powershell.exe\" OR Image=\"*\\\\pwsh.exe\") (CommandLine=\"*-enc*\" OR CommandLine=\"*FromBase64String*\" OR CommandLine=\"*DownloadString*\")\n| table _time host User CommandLine ParentImage",
        "elastic": "process.name : (\"powershell.exe\" or \"pwsh.exe\") and process.command_line : (*-enc* or *EncodedCommand* or *FromBase64String* or *DownloadString*)"},
    "T1486": {"name": "Data Encrypted for Impact / Inhibit System Recovery (T1490)", "kql":
        "DeviceProcessEvents\n| where Timestamp > ago(7d)\n"
        "| where (FileName =~ \"vssadmin.exe\" and ProcessCommandLine has_all (\"delete\", \"shadows\"))\n"
        "    or (FileName =~ \"wmic.exe\" and ProcessCommandLine has_all (\"shadowcopy\", \"delete\"))\n"
        "    or (FileName =~ \"bcdedit.exe\" and ProcessCommandLine has_any (\"recoveryenabled no\", \"ignoreallfailures\"))\n"
        "| project Timestamp, DeviceName, AccountName, ProcessCommandLine",
        "spl": "index=* sourcetype=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1 earliest=-7d\n"
        "((Image=\"*\\\\vssadmin.exe\" CommandLine=\"*delete*shadows*\") OR (Image=\"*\\\\wmic.exe\" CommandLine=\"*shadowcopy*delete*\") OR (Image=\"*\\\\bcdedit.exe\" CommandLine=\"*recoveryenabled*no*\"))\n| table _time host User CommandLine",
        "elastic": "(process.name : \"vssadmin.exe\" and process.args : \"delete\" and process.args : \"shadows\") or (process.name : \"bcdedit.exe\" and process.args : (\"recoveryenabled\" or \"ignoreallfailures\"))"},
    "T1021": {"name": "Remote Services (RDP)", "kql":
        "DeviceLogonEvents\n| where Timestamp > ago(7d)\n| where LogonType == \"RemoteInteractive\" and ActionType == \"LogonSuccess\"\n"
        "| summarize Logons = count(), Devices = dcount(DeviceName) by AccountName, RemoteIP\n| where Devices > 3\n| order by Devices desc",
        "spl": "index=* sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=10 earliest=-7d\n| stats count dc(host) as devices by Account_Name, Source_Network_Address\n| where devices > 3\n| sort - devices",
        "elastic": "event.code : \"4624\" and winlog.logon.type : \"RemoteInteractive\" and event.outcome : \"success\""},
    "T1555": {"name": "Credentials from Password Stores", "kql":
        "DeviceProcessEvents\n| where Timestamp > ago(7d)\n| where ProcessCommandLine has_any (\"vaultcmd\", \"cmdkey /list\", \"lazagne\", \"sekurlsa\", \"mimikatz\")\n"
        "| project Timestamp, DeviceName, AccountName, ProcessCommandLine",
        "spl": "index=* sourcetype=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1 earliest=-7d\n(CommandLine=\"*vaultcmd*\" OR CommandLine=\"*cmdkey /list*\" OR CommandLine=\"*lazagne*\" OR CommandLine=\"*sekurlsa*\")\n| table _time host User CommandLine",
        "elastic": "process.command_line : (*vaultcmd* or *\"cmdkey /list\"* or *lazagne* or *sekurlsa* or *mimikatz*)"},
    "T1105": {"name": "Ingress Tool Transfer", "kql":
        "DeviceProcessEvents\n| where Timestamp > ago(7d)\n"
        "| where (FileName =~ \"certutil.exe\" and ProcessCommandLine has_any (\"-urlcache\", \"-split\", \"http\"))\n"
        "    or (FileName =~ \"bitsadmin.exe\" and ProcessCommandLine has \"/transfer\")\n"
        "| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName",
        "spl": "index=* sourcetype=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1 earliest=-7d\n((Image=\"*\\\\certutil.exe\" CommandLine=\"*urlcache*\") OR (Image=\"*\\\\bitsadmin.exe\" CommandLine=\"*/transfer*\"))\n| table _time host User CommandLine ParentImage",
        "elastic": "(process.name : \"certutil.exe\" and process.args : (\"-urlcache\" or \"-split\")) or (process.name : \"bitsadmin.exe\" and process.args : \"/transfer\")"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "kql":
        "DeviceNetworkEvents\n| where Timestamp > ago(7d)\n| where ActionType == \"ConnectionSuccess\" and RemoteIPType == \"Public\"\n"
        "| summarize Connections = count(), Ports = dcount(RemotePort) by DeviceName, InitiatingProcessFileName, RemoteIP\n| where Connections > 500\n| order by Connections desc",
        "spl": "index=* sourcetype=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=3 earliest=-7d Initiated=true\n| stats count dc(DestinationPort) as ports by host, Image, DestinationIp\n| where count > 500\n| sort - count",
        "elastic": "event.category : \"network\" and network.direction : \"egress\""},
}


def _observed_techniques(db_path: str) -> Counter:
    """Antal indikatorer per teknik-id, utifrån familjerna bakom IOC:erna."""
    counts = Counter()
    if not classify_family:
        return counts
    try:
        conn = sqlite3.connect(db_path)
        fams = Counter(r[0] for r in conn.execute("SELECT family FROM ioc_scores WHERE family != ''"))
        conn.close()
    except sqlite3.Error:
        return counts
    for fam, n in fams.items():
        try:
            _cat, techs = classify_family(fam)
        except Exception:
            continue
        for tid, _name in techs:
            counts[tid.split(".")[0]] += n
    return counts


def build_technique_queries(db_path: str = DB_PATH) -> list:
    observed = _observed_techniques(db_path)
    items = []
    for tid, t in TECHNIQUES.items():
        n = observed.get(tid, 0)
        items.append((n, {"title": f"{tid} {t['name']}" + (f" (observerad hos {n} indikatorer)" if n else ""),
                          "kql": t["kql"], "spl": t["spl"], "elastic": t["elastic"]}))
    items.sort(key=lambda x: -x[0])
    return [i for _n, i in items]


# ------------------------------------------------------------------ KEV-frågor
def build_kev_queries(db_path: str = DB_PATH) -> list:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=14)).strftime("%Y-%m-%d")
    try:
        conn = sqlite3.connect(db_path)
        titles = [r[0] for r in conn.execute(
            "SELECT title FROM articles WHERE feed = 'CISA KEV' AND substr(fetched_at,1,10) >= ?", (cutoff,))]
        conn.close()
    except sqlite3.Error:
        return []
    cves = list(dict.fromkeys(m.upper() for t in titles for m in re.findall(r"CVE-\d{4}-\d{4,7}", t, re.I)))[:100]
    if not cves:
        return []
    return [{"title": f"Nya aktivt utnyttjade sårbarheter ({len(cves)} st, 14 dagar)",
             "kql": f"// Kräver Defender Vulnerability Management\nlet kev = dynamic([{_list(cves)}]);\nDeviceTvmSoftwareVulnerabilities\n| where CveId in (kev)\n"
                    "| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel\n| order by CveId asc",
             "spl": f"// Kräver sårbarhetsdata i Splunk (t.ex. Tenable, Qualys eller Nessus)\nindex=vulnerability cve IN ({_list(cves)})\n| stats values(cve) as cves by dest, signature",
             "elastic": f"vulnerability.id : ({_list(cves, ' or ')})"}]


# ------------------------------------------------------------------ Navigator
def build_navigator_layers(db_path: str = DB_PATH) -> dict:
    """{'alla': lager, 'senaste30': lager}. Tomt om attack_mapping eller poäng saknas."""
    if not classify_family:
        return {}
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
    try:
        conn = sqlite3.connect(db_path)
        rows = conn.execute("SELECT family, last_seen FROM ioc_scores WHERE family != ''").fetchall()
        conn.close()
    except sqlite3.Error:
        return {}
    layers = {}
    for key, title, since in (("alla", "CTI-agent: alla indikatorer", ""), ("senaste30", "CTI-agent: senaste 30 dagarna", cutoff)):
        counts, fams = Counter(), {}
        for fam, last in rows:
            if since and (last or "") < since:
                continue
            try:
                _cat, techs = classify_family(fam)
            except Exception:
                continue
            for tid, name in techs:
                counts[tid] += 1
                fams.setdefault(tid, {"name": name, "families": Counter()})["families"][fam] += 1
        if not counts:
            continue
        mx = max(counts.values())
        layers[key] = {
            "name": title,
            "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": f"Genererad av CTI-agent {datetime.now(timezone.utc).strftime('%Y-%m-%d')}. Poäng = antal indikatorer vars familj använder tekniken.",
            "sorting": 3,
            "layout": {"layout": "side", "showID": True, "showName": True},
            "hideDisabled": False,
            "techniques": [
                {"techniqueID": tid, "score": c, "comment": "Familjer: " + ", ".join(f for f, _n in fams[tid]["families"].most_common(5))}
                for tid, c in counts.most_common()
            ],
            "gradient": {"colors": ["#ffe766ff", "#ff6666ff"], "minValue": 1, "maxValue": mx},
            "legendItems": [], "metadata": [], "showTacticRowBackground": False, "selectTechniquesAcrossTactics": True,
        }
    return layers


# ------------------------------------------------------------------ visning
HUNTING_CSS = """
  .hu-tabs { display: flex; gap: 0.4rem; flex-wrap: wrap; margin-bottom: 0.7rem; align-items: center; }
  .hu-tabs button { background: var(--panel); color: var(--text); border: 1px solid var(--panel-border); border-radius: 6px; padding: 0.3rem 0.7rem; font-size: 0.8rem; cursor: pointer; font-family: inherit; }
  .hu-tabs button.active { border-color: var(--amber); color: var(--amber); }
  .hu-q { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 6px; margin-bottom: 0.7rem; }
  .hu-q h5 { margin: 0; padding: 0.45rem 0.8rem; font-size: 0.82rem; display: flex; justify-content: space-between; gap: 0.5rem; align-items: center; border-bottom: 1px solid var(--panel-border); }
  .hu-q pre { margin: 0; padding: 0.6rem 0.8rem; font-size: 0.76rem; overflow-x: auto; max-height: 230px; white-space: pre; font-family: var(--mono, monospace); }
  .hu-q button { background: none; border: 1px solid var(--panel-border); border-radius: 5px; color: var(--text-dim); font-size: 0.72rem; padding: 0.1rem 0.5rem; cursor: pointer; }
  .hu-group { font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-dim); margin: 0.9rem 0 0.4rem; }
  .hu-nav { margin-top: 1rem; display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; }
"""

_JS = r"""
(function () {
  var D = __DATA__, NAV = __NAV__;
  var root = document.getElementById("huRoot"); if (!root) return;
  var plat = "kql", names = { kql: "Defender / Sentinel (KQL)", spl: "Splunk (SPL)", elastic: "Elastic (KQL)" };
  function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
  function dl(name, text, type) { var a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([text], { type: type || "text/plain" })); a.download = name; document.body.appendChild(a); a.click(); a.remove(); }
  function render() {
    var h = "";
    D.forEach(function (g) {
      if (!g.items.length) return;
      h += '<div class="hu-group">' + esc(g.group) + "</div>";
      g.items.forEach(function (q, i) {
        h += '<div class="hu-q"><h5><span>' + esc(q.title) + '</span><button type="button" data-copy="' + g.id + "|" + i + '">Kopiera</button></h5><pre>' + esc(q[plat]) + "</pre></div>";
      });
    });
    document.getElementById("huOut").innerHTML = h || '<p class="empty">Inga frågor ännu. De skapas när det finns poängsatta indikatorer.</p>';
  }
  root.querySelectorAll("[data-plat]").forEach(function (b) {
    b.addEventListener("click", function () { plat = b.getAttribute("data-plat"); root.querySelectorAll("[data-plat]").forEach(function (x) { x.classList.toggle("active", x === b); }); render(); });
  });
  root.addEventListener("click", function (e) {
    var c = e.target.closest("[data-copy]");
    if (c) { var p = c.getAttribute("data-copy").split("|"), g = D.filter(function (x) { return x.id === p[0]; })[0]; var t = g.items[+p[1]][plat];
      (navigator.clipboard ? navigator.clipboard.writeText(t) : Promise.reject()).then(function () { c.textContent = "Kopierat"; setTimeout(function () { c.textContent = "Kopiera"; }, 1200); }, function () { c.textContent = "Markera och kopiera manuellt"; }); return; }
    var d = e.target.closest("[data-dl]");
    if (d) {
      var k = d.getAttribute("data-dl");
      if (k === "all") { var t2 = ""; D.forEach(function (g) { g.items.forEach(function (q) { t2 += "// ===== " + q.title + " =====\n" + q[plat] + "\n\n"; }); }); dl("hunting-" + plat + ".txt", t2); }
      else if (NAV[k]) dl("navigator-" + k + ".json", JSON.stringify(NAV[k], null, 1), "application/json");
    }
  });
  render();
})();
"""


def build_hunting_html(db_path: str = DB_PATH) -> str:
    groups = [
        {"id": "ioc", "group": "IOC-träffar", "items": build_ioc_queries(db_path)},
        {"id": "ttp", "group": "Beteenden per ATT&CK-teknik", "items": build_technique_queries(db_path)},
        {"id": "kev", "group": "Sårbarheter", "items": build_kev_queries(db_path)},
    ]
    layers = build_navigator_layers(db_path)
    nav_buttons = "".join(
        f'<button type="button" data-dl="{k}">Navigator: {html.escape(l["name"].replace("CTI-agent: ", ""))}</button>' for k, l in layers.items())
    tech_rows = ""
    if "alla" in layers:
        tech_rows = "".join(
            f'<tr><td><a href="https://attack.mitre.org/techniques/{t["techniqueID"].replace(".", "/")}/" target="_blank" rel="noopener">{html.escape(t["techniqueID"])}</a></td>'
            f'<td>{t["score"]}</td><td>{html.escape(t["comment"].replace("Familjer: ", ""))}</td></tr>'
            for t in layers["alla"]["techniques"][:15])
        tech_rows = ('<div class="hu-group">Vanligaste tekniker (topp 15)</div><table class="ic-table"><tr><th>Teknik</th><th>Indikatorer</th><th>Familjer</th></tr>'
                     + tech_rows + "</table>")
    data = json.dumps(groups, ensure_ascii=False).replace("</", "<\\/")
    nav = json.dumps(layers, ensure_ascii=False).replace("</", "<\\/")
    return (
        '<div id="huRoot"><div class="hu-tabs"><span class="dim">Plattform:</span>'
        '<button type="button" class="active" data-plat="kql">Defender / Sentinel</button>'
        '<button type="button" data-plat="spl">Splunk</button><button type="button" data-plat="elastic">Elastic</button>'
        '<button type="button" data-dl="all" style="margin-left:auto">Ladda ner alla</button></div>'
        '<div id="huOut"></div>'
        + (f'<div class="hu-nav"><span class="dim">ATT&amp;CK Navigator-lager:</span>{nav_buttons}</div>' if nav_buttons else "")
        + tech_rows +
        '<p class="dim" style="font-size:0.78rem;white-space:normal;margin-top:0.8rem">Frågorna är startpunkter och körs aldrig automatiskt. '
        'Kontrollera tabell- och fältnamn mot din miljö. Navigator-lagren läses in via Open Existing Layer, Upload from local, på '
        '<a href="https://mitre-attack.github.io/attack-navigator/" target="_blank" rel="noopener">mitre-attack.github.io/attack-navigator</a>.</p></div>'
        f"<script>{_JS.replace('__DATA__', data).replace('__NAV__', nav)}</script>"
    )


if __name__ == "__main__":
    for g in build_ioc_queries():
        print(g["title"])
