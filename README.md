# CTI-agent

Autonom agent för hotunderrättelser (CTI) med fokus på nordisk offentlig sektor och transport.
Den körs varje timme i GitHub Actions, samlar in data från öppna källor, sparar i SQLite
(`cti.db`) och publicerar en fristående instrumentpanel (`index.html`) via GitHub Pages.

Panel: https://ddbar78-create.github.io/CTI-agent/

## Vad den gör

- Hämtar IOC:er och hot från ThreatFox, URLhaus, Feodo Tracker, MalwareBazaar och (valfritt) AlienVault OTX
- Följer ransomware-offer via ransomware.live, Telegram-kanaler och ett antal RSS-flöden
- Berikar CVE:er med CVSS, EPSS och CISA KEV, samt följer nya KEV-poster
- Skannar din bevakningslista (organisationer/domäner) och din teknikbevakning (produkter)
- Kartlägger malware-familjer mot MITRE ATT&CK
- Bygger panelen: sök och rapport, aktörsprofiler, hotaktörskarta, trender, karta, källstatus, export
- Exporterar blocklistor, CSV och STIX 2.1 till `exports/`

## Filer

| Fil | Roll |
|---|---|
| `agent.py` | Huvudprogram, kör alla källor och bygger panelen |
| `storage.py` | SQLite-schema, migreringar, sparfunktioner |
| `more_sources.py` | KEV, URLhaus, Feodo, MalwareBazaar, OTX och extra RSS |
| `run_status.py` | Källstatus per körning (visas överst i panelen) |
| `patch_stats.py` | Patchstatistik för Windows och Linux (Microsoft, Red Hat, Ubuntu, CISA KEV) |
| `ai_watch.py` | AI-hot: nyckelordsbevakning av AI-relaterade hot |
| `daily_digest.py` | Dagsrapport per dag, som standard gårdagen |
| `ransomlook.py` | Extra ransomware-källa (RansomLook), komplement till ransomware.live |
| `source_catalog.py` | Statistik över deepdarkCTI-källor (endast antal, inga adresser) |
| `intel.py` | CVE-riskpoäng, entitetssök, relationsgraf, avvikelselarm, sektorrapport |
| `notifier.py` | Larm via mejl, Discord, Teams eller ntfy-push |
| `threat_actor_map.py` | Hotaktörskarta: ransomware-grupper, deras offer per land och bransch |
| `export_feeds.py` | CSV, blocklistor och STIX till `exports/` |
| `generate_report.py` | Bygger `index.html` |
| `search_report.py` | Sök, rapport, Sigma och YARA i panelen |
| `actor_profiles.py` | Aktörs- och familjeprofiler |
| `tech_watch.py`, `tech_watchlist.py` | Teknikbevakning, lista dina produkter i den senare |
| `watchlist.py` | Dina organisationer och domäner att bevaka |
| `attack_mapping.py`, `sector_watch.py`, `telegram_channels.py` | Mappning, sektorer, kanaler |
| `daily_briefing.py` | Dygnssammanfattning utan LLM |
| `.github/workflows/cti-agent.yml` | Schemaläggning |

## Installation från noll

1. Skapa ett publikt repo och ladda upp alla filer ovan (Add file, Upload files, eller klistra in via webben).
2. Lägg workflow-filen i `.github/workflows/cti-agent.yml`.
3. Settings, Secrets and variables, Actions, New repository secret:
   - `THREATFOX_AUTH_KEY` (gratis abuse.ch-nyckel, används även för URLhaus och MalwareBazaar)
   - `SHODAN_API_KEY`
   - `OTX_API_KEY` (valfri, gratis hos otx.alienvault.com)
   - `ANTHROPIC_API_KEY` (valfri, LLM-berikning är avstängd utan den)
4. Settings, Actions, General, Workflow permissions: välj **Read and write permissions**.
5. Settings, Pages: Source = Deploy from a branch, branch `main`, mapp `/ (root)`.
6. Actions, CTI agent, Run workflow. Första körningen tar några minuter.

## Anpassa

- `watchlist.py`: byt ut platshållaren "Exempelkommun" mot dina egna organisationer och domäner.
- `tech_watchlist.py`: ändra listan till de produkter du faktiskt kör. Var specifik med nyckelorden.
- Retention: ThreatFox-data sparas 7 dagar, övrigt längre. Gamla poster rensas automatiskt.

## Notiser

Larm från panelen (avvikelser, nordiska offer inom transport/offentlig sektor, KEV som berör din teknik)
kan skickas ut. Alla kanaler är valfria. Lägg de du vill ha som secrets (Settings, Secrets and variables, Actions):

| Kanal | Secrets |
|---|---|
| Discord | `DISCORD_WEBHOOK_URL` |
| Teams | `TEAMS_WEBHOOK_URL` |
| Push till mobilen (ntfy.sh, gratis) | `NTFY_TOPIC` (välj ett långt hemligt namn, prenumerera på det i appen ntfy) |
| Mejl | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `MAIL_TO` (Gmail: smtp.gmail.com, 587, applösenord) |

Samma larm skickas bara en gång. Standard är nivå Hög och Kritisk, ändra `MIN_LEVEL` i `notifier.py`.
Branscher som bevakas ändras i `SECTOR_FOCUS` i `intel.py`.

## Exporter

Finns under `exports/` och via Pages, t.ex. `.../exports/blocklist-domains.txt`.
Blocklistor och STIX innehåller bara IOC:er med confidence 75 eller högre.
Granska alltid innan du blockerar i produktion. Regex-plockade värden ur artiklar ingår bara i `iocs.csv`.

## Licenser och villkor

- ThreatFox, URLhaus, Feodo och MalwareBazaar är CC0.
- OpenPhish ingår inte, eftersom deras villkor förbjuder vidaredistribution.
- Shodan- och OTX-data i ett publikt repo kan strida mot deras villkor. Kontrollera detta, eller gör repot privat.

## Felsökning

- Kontrollera radantal efter inklistring, avkortade filer är vanligaste felet.
- Sök på `Traceback` i Actions-loggen. GitHub visar felutskrifter före vanlig utskrift.
- Panelen visar källstatus överst. En röd källa betyder ofta en ändrad RSS-adress.
- crt.sh svarar ibland 502, det är ofarligt.
- Källstatus fylls först efter första körningen med de nya filerna.
