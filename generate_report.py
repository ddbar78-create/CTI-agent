"""
Genererar index.html — en fristående instrumentpanel över allt agenten
samlat in. Ingen server, inget ramverk, bara en enda HTML-fil med
inbäddad CSS/JS, byggd direkt ur cti.db.

Körs som sista steg i agent.py. Committas till repot av GitHub Actions
precis som cti.db, och kan publiceras gratis via GitHub Pages
(Settings -> Pages -> Deploy from branch -> main / root).
"""

import html
import json
import sqlite3
from datetime import datetime, timezone

from storage import DB_PATH
from attack_mapping import parse_family_from_value, classify_family

OUTPUT_PATH = "index.html"


def _rows(conn, query, params=()):
    cur = conn.cursor()
    cur.execute(query, params)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def _esc(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def _section(section_id: str, title: str, body_html: str) -> str:
    """Wrappar en sektion med klickbar, ihopfällbar rubrik (för interaktivitet)."""
    return f'''
  <section id="{section_id}">
    <h2 class="section-header" onclick="toggleSection('{section_id}')">
      <span class="chevron" id="{section_id}-chevron">▾</span> {title}
    </h2>
    <div class="section-body" id="{section_id}-body">
      {body_html}
    </div>
  </section>'''


def _table_block(headers: list, rows_html: str, table_id: str, searchable: bool = False) -> str:
    """
    Bygger en tabell med valfria sorterbara kolumner och valfri sökruta.
    headers: lista av (label, sort_type) där sort_type är "text", "number"
    eller None (ingen sortering för den kolumnen).
    """
    ths = []
    for i, (label, stype) in enumerate(headers):
        if stype:
            ths.append(
                f'<th class="sortable" onclick="sortTable(\'{table_id}\', {i}, \'{stype}\')">'
                f'{_esc(label)} <span class="sort-arrow"></span></th>'
            )
        else:
            ths.append(f"<th>{_esc(label)}</th>")
    thead = "<tr>" + "".join(ths) + "</tr>"

    search_html = ""
    if searchable:
        search_html = (
            f'<div class="controls">'
            f'<input type="search" id="{table_id}Search" placeholder="Sök..." '
            f'oninput="filterTable(\'{table_id}Search\', \'{table_id}\')"></div>'
        )

    return f'''{search_html}
    <div class="table-scroll">
      <table id="{table_id}">
        <thead>{thead}</thead>
        <tbody>{rows_html}</tbody>
      </table>
    </div>'''


# Ungefärliga centroider (lat, lon) för länder som vanligen förekommer i
# ransomware.live-data. Räcker inte alla världens länder att göra kartan
# meningsfull, men täcker de vanligaste. Okända landskoder listas separat
# under kartan istället för att tappas bort helt.
COUNTRY_CENTROIDS = {
    "US": (39.8, -98.6), "CA": (56.1, -106.3), "MX": (23.6, -102.6),
    "BR": (-14.2, -51.9), "AR": (-38.4, -63.6), "CL": (-35.7, -71.5),
    "GB": (55.4, -3.4), "IE": (53.4, -8.2), "FR": (46.6, 2.2),
    "DE": (51.2, 10.5), "ES": (40.5, -3.7), "PT": (39.4, -8.2),
    "IT": (41.9, 12.6), "NL": (52.1, 5.3), "BE": (50.5, 4.5),
    "CH": (46.8, 8.2), "AT": (47.5, 14.6), "SE": (60.1, 18.6),
    "NO": (60.5, 8.5), "DK": (56.3, 9.5), "FI": (61.9, 25.7),
    "IS": (64.9, -19.0),
    "PL": (51.9, 19.1), "CZ": (49.8, 15.5), "GR": (39.1, 21.8),
    "RU": (61.5, 105.3), "UA": (48.4, 31.2), "TR": (38.9, 35.2),
    "IL": (31.0, 34.8), "SA": (23.9, 45.1), "AE": (23.4, 53.8),
    "ZA": (-30.6, 22.9), "NG": (9.1, 8.7), "EG": (26.8, 30.8),
    "IN": (20.6, 79.0), "PK": (30.4, 69.3), "CN": (35.9, 104.2),
    "JP": (36.2, 138.3), "KR": (35.9, 127.8), "TW": (23.7, 121.0),
    "PH": (12.9, 121.8), "VN": (14.1, 108.3), "TH": (15.9, 100.9),
    "MY": (4.2, 102.0), "SG": (1.35, 103.8), "ID": (-0.8, 113.9),
    "AU": (-25.3, 133.8), "NZ": (-41.0, 174.9),
    "RS": (44.0, 21.0), "HR": (45.1, 15.2), "RO": (45.9, 25.0),
    "HU": (47.2, 19.5), "BG": (42.7, 25.5), "SK": (48.7, 19.7),
}


def _real_world_map_block(country_counts: list, victim_details: dict, element_id: str = "worldMap") -> str:
    """
    Bygger ett HTML/JS-block som ritar en RIKTIG världskarta (faktiska
    landgränser) med D3.js + en etablerad world-atlas TopoJSON-fil,
    laddade via CDN i webbläsaren när sidan öppnas. Kräver internetuppkoppling
    hos den som tittar på dashboarden (helt normalt för en webbsida).

    Bubblor för varje land ritas ovanpå kartan baserat på COUNTRY_CENTROIDS.
    Klick på en bubbla visar offer/grupper för det landet i en detaljpanel.
    En "Ladda ner som PNG"-knapp låter dig exportera kartan för presentationer.
    """
    if not country_counts:
        return '<p class="empty">Ingen geografisk data ännu.</p>'

    data_points = [
        {
            "country": c["country"], "n": c["n"],
            "lat": COUNTRY_CENTROIDS[c["country"]][0],
            "lon": COUNTRY_CENTROIDS[c["country"]][1],
            "victims": victim_details.get(c["country"], []),
        }
        for c in country_counts if c["country"] in COUNTRY_CENTROIDS
    ]
    unplotted = [c for c in country_counts if c["country"] not in COUNTRY_CENTROIDS]
    data_json = json.dumps(data_points, ensure_ascii=False)

    unplotted_note = ""
    if unplotted:
        listed = ", ".join(f'{_esc(c["country"])} ({c["n"]})' for c in unplotted)
        unplotted_note = f'<p class="dim" style="margin-top:0.6rem;">Utanför kartans landslista: {listed}</p>'

    return f"""
    <div class="map-toolbar">
      <button onclick="downloadMapAsPng()" class="map-download-btn">⬇ Ladda ner karta som PNG</button>
    </div>
    <div id="{element_id}" class="world-map-container"></div>
    <div id="{element_id}Details" class="map-details-panel">
      <span class="dim">Klicka på en bubbla för att se vilka offer/grupper som ligger bakom siffran.</span>
    </div>
    {unplotted_note}
    <script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/topojson/3.0.2/topojson.min.js"></script>
    <script>
    (function() {{
      const victimData = {data_json};
      const container = document.getElementById("{element_id}");
      const width = container.clientWidth || 1000;
      const height = width * 0.5;

      const svg = d3.select(container).append("svg")
        .attr("viewBox", `0 0 ${{width}} ${{height}}`)
        .attr("width", "100%")
        .attr("height", height)
        .style("background", "#0a0d13")
        .style("border-radius", "8px");

      svg.append("defs").html(`
        <filter id="mapGlow" x="-100%" y="-100%" width="300%" height="300%">
          <feGaussianBlur stdDeviation="5" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
      `);

      const projection = d3.geoNaturalEarth1();
      const path = d3.geoPath(projection);

      d3.json("https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json").then(world => {{
        const countries = topojson.feature(world, world.objects.countries);
        projection.fitSize([width, height], countries);

        svg.append("g").selectAll("path")
          .data(countries.features)
          .join("path")
          .attr("d", path)
          .attr("fill", "#1c2433")
          .attr("stroke", "#2e3646")
          .attr("stroke-width", 0.6);

        const maxN = d3.max(victimData, d => d.n) || 1;
        const radius = d3.scalePow().exponent(0.5).domain([0, maxN]).range([5, 28]);
        const color = d3.scaleLinear().domain([0, maxN]).range(["#e8a33d", "#d9534f"]);

        const bubbles = svg.append("g").selectAll("g")
          .data(victimData)
          .join("g")
          .attr("transform", d => {{
            const p = projection([d.lon, d.lat]);
            return `translate(${{p[0]}},${{p[1]}})`;
          }})
          .style("cursor", "pointer")
          .on("click", function(event, d) {{
            svg.selectAll("circle.bubble-main").attr("stroke-width", 1);
            d3.select(this).select("circle.bubble-main").attr("stroke-width", 3);

            const panel = document.getElementById("{element_id}Details");
            const victimList = d.victims.map(v =>
              `<li><strong>${{v.group}}</strong> → ${{v.victim}}</li>`
            ).join("");
            panel.innerHTML = `
              <div class="map-details-header">${{d.country}} — ${{d.n}} rapporterade offer</div>
              <ul class="map-details-list">${{victimList || "<li>Ingen detaljerad offerinfo sparad ännu.</li>"}}</ul>
            `;
          }});

        bubbles.append("circle")
          .attr("class", "bubble-main")
          .attr("r", d => radius(d.n))
          .attr("fill", d => color(d.n))
          .attr("fill-opacity", 0.75)
          .attr("stroke", d => color(d.n))
          .attr("stroke-width", 1)
          .attr("filter", "url(#mapGlow)");

        bubbles.append("text")
          .text(d => `${{d.country}} (${{d.n}})`)
          .attr("y", d => -radius(d.n) - 6)
          .attr("text-anchor", "middle")
          .attr("font-size", 11)
          .attr("font-weight", 600)
          .attr("fill", "#e8ecf2")
          .attr("style", "paint-order: stroke; stroke: #0a0d13; stroke-width: 3px;");
      }}).catch(err => {{
        container.innerHTML = '<p style="color:#7a8394; font-style:italic; padding:2rem;">Kunde inte ladda kartdata (kräver internetuppkoppling). Fel: ' + err + '</p>';
      }});
    }})();

    function downloadMapAsPng() {{
      const svgEl = document.querySelector("#{element_id} svg");
      if (!svgEl) return;
      const svgData = new XMLSerializer().serializeToString(svgEl);
      const svgBlob = new Blob([svgData], {{type: "image/svg+xml;charset=utf-8"}});
      const url = URL.createObjectURL(svgBlob);
      const img = new Image();
      img.onload = function() {{
        const scale = 2;
        const canvas = document.createElement("canvas");
        canvas.width = svgEl.clientWidth * scale;
        canvas.height = svgEl.clientHeight * scale;
        const ctx = canvas.getContext("2d");
        ctx.fillStyle = "#0a0d13";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.scale(scale, scale);
        ctx.drawImage(img, 0, 0);
        URL.revokeObjectURL(url);
        const link = document.createElement("a");
        link.download = "ransomware-varldskarta.png";
        link.href = canvas.toDataURL("image/png");
        link.click();
      }};
      img.src = url;
    }}
    </script>
    """


def _svg_trend_chart(dates: list, series: dict, width: int = 1000, height: int = 200) -> str:
    """
    Bygger en enkel, beroendefri SVG-linjegraf MED hover-tooltips.
    series: {namn: (lista_med_värden, färg)} — alla listor måste vara lika
    långa som dates. Varje anrop ritar sin egen skala (max = högsta värdet
    bland de serier som skickas in), så ge inte in serier med väldigt olika
    storleksordning i samma anrop — dela upp i flera diagram istället.
    """
    if not dates:
        return '<p class="empty">Ingen trenddata ännu — kommer synas efter några dagars körning.</p>'

    all_values = [v for values, _ in series.values() for v in values]
    max_val = max(all_values) if any(all_values) else 1

    n = len(dates)
    pad_l, pad_r, pad_t, pad_b = 45, 15, 15, 28
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b

    def px(i):
        return pad_l + (i / max(n - 1, 1)) * plot_w

    def py(v):
        return pad_t + plot_h - (v / max_val) * plot_h

    parts = [
        f'<line x1="{pad_l}" y1="{pad_t}" x2="{pad_l}" y2="{height - pad_b}" stroke="#262d3a" />',
        f'<line x1="{pad_l}" y1="{height - pad_b}" x2="{width - pad_r}" y2="{height - pad_b}" stroke="#262d3a" />',
        f'<text x="4" y="{pad_t + 4}" font-size="10" fill="#7a8394">{max_val}</text>',
    ]

    for name, (values, color) in series.items():
        points = " ".join(f"{px(i):.1f},{py(v):.1f}" for i, v in enumerate(values))
        parts.append(f'<polyline fill="none" stroke="{color}" stroke-width="2" points="{points}" />')
        for i, v in enumerate(values):
            # Synlig liten prick
            parts.append(f'<circle cx="{px(i):.1f}" cy="{py(v):.1f}" r="2.5" fill="{color}" style="pointer-events:none;" />')
            # Osynlig större "hit area" för enklare hovring, bär tooltip-datan
            tooltip_text = _esc(f"{name} · {dates[i]}: {v}")
            parts.append(
                f'<circle class="chart-point" cx="{px(i):.1f}" cy="{py(v):.1f}" r="9" '
                f'fill="transparent" data-tooltip="{tooltip_text}" />'
            )

    step = max(1, n // 8)
    for i in range(0, n, step):
        parts.append(
            f'<text x="{px(i):.1f}" y="{height - 6}" font-size="10" fill="#7a8394" '
            f'text-anchor="middle">{_esc(dates[i][5:])}</text>'
        )

    legend = "".join(
        f'<span class="legend-item"><span class="legend-dot" style="background:{color}"></span>{_esc(name)}</span>'
        for name, (_, color) in series.items()
    )

    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}">'
        + "".join(parts)
        + "</svg>"
        + f'<div class="legend">{legend}</div>'
    )


def generate_report(db_path: str = DB_PATH, output_path: str = OUTPUT_PATH):
    conn = sqlite3.connect(db_path)

    stats = _rows(conn, "SELECT COUNT(*) AS n FROM articles")[0]["n"]
    ioc_stats = _rows(conn, "SELECT COUNT(*) AS n FROM iocs")[0]["n"]
    full_text_count = _rows(
        conn,
        "SELECT COUNT(*) AS n FROM articles WHERE full_text IS NOT NULL AND full_text != ''",
    )[0]["n"]

    ioc_type_breakdown = _rows(
        conn,
        """
        SELECT ioc_type, COUNT(*) AS n FROM iocs
        GROUP BY ioc_type ORDER BY n DESC
        """,
    )
    max_type_count = max((r["n"] for r in ioc_type_breakdown), default=1)

    ransomware_victims = _rows(
        conn,
        """
        SELECT title, link, published, fetched_at FROM articles
        WHERE feed = 'ransomware.live'
        ORDER BY id DESC LIMIT 25
        """,
    )

    high_severity = _rows(
        conn,
        """
        SELECT title, link, llm_actor, llm_sector, llm_severity, llm_summary, fetched_at
        FROM articles
        WHERE llm_severity IN ('high', 'critical')
        ORDER BY id DESC LIMIT 25
        """,
    )

    recent_iocs = _rows(
        conn,
        """
        SELECT iocs.ioc_type, iocs.value, articles.title, articles.link, articles.feed
        FROM iocs
        JOIN articles ON articles.id = iocs.article_id
        ORDER BY iocs.id DESC LIMIT 200
        """,
    )

    recent_articles = _rows(
        conn,
        """
        SELECT feed, title, link, published, fetched_at,
               (full_text IS NOT NULL AND full_text != '') AS has_full_text
        FROM articles
        WHERE feed != 'ransomware.live' AND feed NOT LIKE 'ThreatFox%'
        ORDER BY id DESC LIMIT 40
        """,
    )

    daily_rows = _rows(
        conn,
        "SELECT * FROM daily_counts ORDER BY date DESC LIMIT 30",
    )
    daily_rows = list(reversed(daily_rows))

    shodan_hits = _rows(
        conn,
        """
        SELECT ip, ports, hostnames, vulns, tags FROM ip_enrichment
        WHERE vulns != '' OR ports != ''
        ORDER BY checked_at DESC LIMIT 30
        """,
    )

    cve_priorities = _rows(
        conn,
        """
        SELECT cve_id, cvss, epss, kev, ransomware_campaign, summary
        FROM cve_enrichment
        ORDER BY kev DESC, epss DESC LIMIT 30
        """,
    )

    domain_infra = _rows(
        conn,
        """
        SELECT domain, related_domains FROM domain_enrichment
        WHERE related_domains != ''
        ORDER BY checked_at DESC LIMIT 20
        """,
    )

    domain_ages = _rows(
        conn,
        """
        SELECT domain, registered_date, age_days, registrar FROM domain_age
        ORDER BY age_days ASC LIMIT 30
        """,
    )

    victim_country_counts = _rows(
        conn,
        """
        SELECT country, COUNT(*) AS n FROM ransomware_victims
        WHERE country IS NOT NULL AND country != ''
        GROUP BY country ORDER BY n DESC
        """,
    )

    victim_details_by_country = {}
    victim_rows_raw = _rows(
        conn,
        """
        SELECT country, group_name, victim FROM ransomware_victims
        WHERE country IS NOT NULL AND country != ''
        ORDER BY id DESC
        """,
    )
    for row in victim_rows_raw:
        bucket = victim_details_by_country.setdefault(row["country"], [])
        if len(bucket) < 25:
            bucket.append({"group": row["group_name"], "victim": row["victim"]})

    # Analysera malware-familjer från ThreatFox-annoterade IOC-värden och
    # mappa dem mot ATT&CK-kategorier. Ren analys av redan insamlad data,
    # ingen extern källa behövs.
    threatfox_values = _rows(
        conn,
        """
        SELECT iocs.value FROM iocs
        JOIN articles ON articles.id = iocs.article_id
        WHERE articles.feed LIKE 'ThreatFox%'
        """,
    )
    family_counts: dict = {}
    for row in threatfox_values:
        family = parse_family_from_value(row["value"])
        if family:
            family_counts[family] = family_counts.get(family, 0) + 1

    attack_rows = []
    for family, count in sorted(family_counts.items(), key=lambda x: -x[1]):
        category, techniques = classify_family(family)
        attack_rows.append({
            "family": family, "count": count, "category": category, "techniques": techniques,
        })

    conn.close()

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # --- Bygg HTML-innehåll för varje sektion ---

    breakdown_html = "\n".join(
        f'''<div class="bar-row" onclick="filterIocsByType('{_esc(r["ioc_type"])}')" title="Klicka för att filtrera IOC-listan">
              <span class="bar-label">{_esc(r["ioc_type"])}</span>
              <div class="bar-track"><div class="bar-fill" style="width:{max(4, r["n"] / max_type_count * 100):.0f}%"></div></div>
              <span class="bar-count">{r["n"]}</span>
            </div>'''
        for r in ioc_type_breakdown
    )

    victims_html = "\n".join(
        f'''<tr>
              <td>{_esc(v["title"])}</td>
              <td class="dim" data-sort="{_esc(v["published"] or v["fetched_at"])}">{_esc(v["published"] or v["fetched_at"])[:10]}</td>
            </tr>'''
        for v in ransomware_victims
    ) or '<tr><td colspan="2" class="empty">Inga ransomware-aviseringar ännu.</td></tr>'

    severity_html = "\n".join(
        f'''<tr>
              <td><span class="badge badge-{_esc(h["llm_severity"])}">{_esc(h["llm_severity"])}</span></td>
              <td>{_esc(h["title"])}</td>
              <td class="dim">{_esc(h["llm_actor"] or "—")}</td>
              <td class="dim">{_esc(h["llm_sector"] or "—")}</td>
            </tr>'''
        for h in high_severity
    ) or '<tr><td colspan="4" class="empty">Inga high/critical-flaggade artiklar ännu (kräver ANTHROPIC_API_KEY).</td></tr>'

    iocs_html = "\n".join(
        f'''<tr data-type="{_esc(i["ioc_type"])}">
              <td class="mono">{_esc(i["ioc_type"])}</td>
              <td class="mono ioc-value">{_esc(i["value"])}</td>
              <td class="dim">{_esc(i["feed"])}</td>
            </tr>'''
        for i in recent_iocs
    ) or '<tr><td colspan="3" class="empty">Inga IOCs ännu.</td></tr>'

    articles_html = "\n".join(
        f'''<tr>
              <td class="dim">{_esc(a["feed"])}</td>
              <td><a href="{_esc(a["link"])}" target="_blank" rel="noopener">{_esc(a["title"])}</a></td>
              <td>{'<span class="badge badge-full-text">Fulltext</span>' if a["has_full_text"] else '<span class="dim">—</span>'}</td>
            </tr>'''
        for a in recent_articles
    ) or '<tr><td colspan="3" class="empty">Inga artiklar ännu.</td></tr>'

    shodan_html = "\n".join(
        f'''<tr>
              <td class="mono">{_esc(s["ip"])}</td>
              <td class="mono dim">{_esc(s["ports"]) or "—"}</td>
              <td>{'<span class="badge badge-critical">' + _esc(s["vulns"]) + '</span>' if s["vulns"] else '—'}</td>
              <td class="dim">{_esc(s["hostnames"]) or "—"}</td>
            </tr>'''
        for s in shodan_hits
    ) or '<tr><td colspan="4" class="empty">Ingen Shodan-data ännu (byggs upp gradvis, ~20 nya IP:er/körning).</td></tr>'

    def _cve_badge(c):
        if c["kev"]:
            return '<span class="badge badge-critical">KEV — aktivt utnyttjad</span>'
        if (c["epss"] or 0) >= 0.5:
            return f'<span class="badge badge-high">EPSS {c["epss"]:.0%}</span>'
        if (c["epss"] or 0) >= 0.1:
            return f'<span class="dim mono">EPSS {c["epss"]:.0%}</span>'
        return f'<span class="dim mono">EPSS {(c["epss"] or 0):.1%}</span>'

    cve_html = "\n".join(
        f'''<tr>
              <td class="mono">{_esc(c["cve_id"])}</td>
              <td data-sort="{(c["kev"] or 0) * 1000 + (c["epss"] or 0) * 100:.2f}">{_cve_badge(c)}</td>
              <td class="dim" data-sort="{c["cvss"] or 0}">{_esc(c["cvss"]) if c["cvss"] else "—"}</td>
              <td class="dim">{_esc((c["summary"] or "")[:90])}{"..." if c["summary"] and len(c["summary"]) > 90 else ""}</td>
            </tr>'''
        for c in cve_priorities
    ) or '<tr><td colspan="4" class="empty">Inga CVE:er prioriterade ännu.</td></tr>'

    domain_infra_html = "\n".join(
        f'''<tr>
              <td class="mono">{_esc(d["domain"])}</td>
              <td class="mono dim ioc-value">{_esc(d["related_domains"])}</td>
            </tr>'''
        for d in domain_infra
    ) or '<tr><td colspan="2" class="empty">Ingen relaterad infrastruktur hittad ännu (byggs upp gradvis).</td></tr>'

    def _age_badge(age_days):
        if age_days is None:
            return '<span class="dim">—</span>'
        if age_days < 30:
            return f'<span class="badge badge-critical">{age_days} dagar — NY</span>'
        if age_days < 180:
            return f'<span class="badge badge-high">{age_days} dagar</span>'
        return f'<span class="dim mono">{age_days} dagar</span>'

    domain_age_html = "\n".join(
        f'''<tr>
              <td class="mono">{_esc(d["domain"])}</td>
              <td data-sort="{d["age_days"] if d["age_days"] is not None else 999999}">{_age_badge(d["age_days"])}</td>
              <td class="dim">{_esc(d["registered_date"]) or "—"}</td>
              <td class="dim">{_esc(d["registrar"]) or "—"}</td>
            </tr>'''
        for d in domain_ages
    ) or '<tr><td colspan="4" class="empty">Ingen domänålder kontrollerad ännu (byggs upp gradvis).</td></tr>'

    world_map_html = _real_world_map_block(victim_country_counts, victim_details_by_country)

    # Gruppera per kategori för en tydligare, mindre repetitiv vy
    category_groups: dict = {}
    for row in attack_rows:
        category_groups.setdefault(row["category"], []).append(row)

    attack_html_parts = []
    for category, rows in sorted(category_groups.items(), key=lambda x: -sum(r["count"] for r in x[1])):
        total = sum(r["count"] for r in rows)
        families_str = ", ".join(f'{_esc(r["family"])} ({r["count"]})' for r in rows[:12])
        techniques = rows[0]["techniques"]  # samma tekniker för hela kategorin
        techniques_html = " · ".join(
            f'<a href="https://attack.mitre.org/techniques/{tid.replace(".", "/")}/" '
            f'target="_blank" rel="noopener">{tid} {_esc(name)}</a>'
            for tid, name in techniques
        )
        attack_html_parts.append(f'''
          <div class="attack-category">
            <div class="attack-category-header">
              <span>{_esc(category)}</span>
              <span class="dim">{total} IOCs</span>
            </div>
            <div class="attack-techniques">{techniques_html}</div>
            <div class="attack-families dim">{families_str}</div>
          </div>''')
    attack_html = "".join(attack_html_parts) or '<p class="empty">Ingen ThreatFox-data att analysera ännu.</p>'

    ioc_types_for_filter = sorted({r["ioc_type"] for r in ioc_type_breakdown})
    filter_options = "\n".join(
        f'<option value="{_esc(t)}">{_esc(t)}</option>' for t in ioc_types_for_filter
    )

    # Två separata diagram — ThreatFox har helt annan skala (tusentals/dag)
    # än de övriga källorna, så en gemensam graf skulle trycka ner de senare
    # till en osynlig platt linje.
    trend_dates = [r["date"] for r in daily_rows]
    threatfox_chart_html = _svg_trend_chart(
        trend_dates,
        {"ThreatFox": ([r["new_iocs_threatfox"] for r in daily_rows], "#e8a33d")},
    )
    other_sources_chart_html = _svg_trend_chart(
        trend_dates,
        {
            "RSS-artiklar": ([r["new_articles"] for r in daily_rows], "#5b8dd6"),
            "RSS/regex-IOCs": ([r["new_iocs_regex"] for r in daily_rows], "#8b6fd6"),
            "Telegram": ([r["new_telegram"] for r in daily_rows], "#4fb3a9"),
            "Ransomware-offer": ([r["new_ransomware_victims"] for r in daily_rows], "#d9534f"),
        },
    )

    # --- Bygg sektionerna (id, titel, innehåll) — används för både
    # innehållsförteckningen och själva sidan ---
    ioc_search_control = (
        f'<div class="controls">'
        f'<select id="typeFilter" onchange="filterIocs()"><option value="">Alla typer</option>{filter_options}</select>'
        f'<input type="search" id="iocSearch" placeholder="Sök värde..." oninput="filterIocs()"></div>'
    )

    sections = [
        ("sec-trend", "Trend, senaste dagarna", f'''
            <div class="chart-grid">
              <div class="chart-panel">
                <div class="chart-title">ThreatFox (hög volym)</div>
                {threatfox_chart_html}
              </div>
              <div class="chart-panel">
                <div class="chart-title">Övriga källor</div>
                {other_sources_chart_html}
              </div>
            </div>'''),
        ("sec-attack", "Malware-familjer mot MITRE ATT&CK", attack_html),
        ("sec-ioctypes", "IOC-typer i databasen (klicka för att filtrera)", breakdown_html),
        ("sec-map", "Geografisk spridning — ransomware-offer", world_map_html),
        ("sec-ransomware", "Senaste ransomware-offeraviseringar",
            _table_block([("Offer", "text"), ("Datum", "text")], victims_html, "ransomwareTable", searchable=True)),
        ("sec-severity", "Hög/kritisk allvarlighet (LLM-flaggat)",
            _table_block([("Nivå", None), ("Titel", None), ("Aktör", None), ("Sektor", None)], severity_html, "severityTable")),
        ("sec-iocs", "Senaste IOCs",
            ioc_search_control + _table_block(
                [("Typ", "text"), ("Värde", "text"), ("Källa", "text")], iocs_html, "iocTable"
            ).replace('<div class="controls">\n    ', "")),
        ("sec-domainage", "Domänålder (RDAP/WHOIS) — nyregistrerade domäner flaggade",
            _table_block([("Domän", "text"), ("Ålder", "number"), ("Registrerad", "text"), ("Registrar", "text")], domain_age_html, "domainAgeTable")),
        ("sec-crtsh", "Relaterad infrastruktur (Certificate Transparency, crt.sh)",
            _table_block([("Domän", "text"), ("Relaterade domäner", None)], domain_infra_html, "crtshTable")),
        ("sec-cve", "CVE-prioritering (EPSS + KEV via Shodan CVEDB)",
            _table_block([("CVE", "text"), ("Status", "number"), ("CVSS", "number"), ("Sammanfattning", None)], cve_html, "cveTable", searchable=True)),
        ("sec-shodan", "IP-berikning (Shodan InternetDB) — öppna portar & kända CVE:er",
            _table_block([("IP", "text"), ("Portar", None), ("CVE:er", None), ("Hostnames", None)], shodan_html, "shodanTable")),
        ("sec-articles", "Senaste artiklar (RSS / Telegram)",
            _table_block([("Källa", "text"), ("Titel", "text"), ("Fulltext", None)], articles_html, "articlesTable", searchable=True)),
    ]

    toc_html = "".join(
        f'<a href="#{sid}" class="toc-link">{title.split("(")[0].split(",")[0].strip()}</a>'
        for sid, title, _ in sections
    )
    sections_html = "".join(_section(sid, title, body) for sid, title, body in sections)

    html_doc = f"""<!DOCTYPE html>
<html lang="sv">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CTI-agent — instrumentpanel</title>
<style>
  :root {{
    --bg: #12161d;
    --panel: #181d26;
    --panel-border: #262d3a;
    --text: #d7dbe3;
    --text-dim: #7a8394;
    --amber: #e8a33d;
    --red: #d9534f;
    --blue: #5b8dd6;
    --mono: 'IBM Plex Mono', 'SF Mono', Consolas, monospace;
    --sans: 'IBM Plex Sans', -apple-system, sans-serif;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    margin: 0;
    padding: 2.5rem 1.5rem 4rem;
    line-height: 1.5;
  }}
  .wrap {{ max-width: 1100px; margin: 0 auto; }}
  header {{ margin-bottom: 1.25rem; }}
  h1 {{
    font-size: 1.5rem;
    font-weight: 600;
    margin: 0 0 0.3rem;
    letter-spacing: -0.01em;
  }}
  .subtitle {{ color: var(--text-dim); font-size: 0.9rem; }}
  .toc {{
    display: flex; flex-wrap: wrap; gap: 0.4rem;
    margin-bottom: 1.75rem; padding-bottom: 1.25rem;
    border-bottom: 1px solid var(--panel-border);
    position: sticky; top: 0; background: var(--bg); z-index: 10; padding-top: 0.5rem;
  }}
  .toc-link {{
    font-size: 0.78rem; color: var(--text-dim); background: var(--panel);
    border: 1px solid var(--panel-border); padding: 0.3rem 0.7rem; border-radius: 20px;
    text-decoration: none; white-space: nowrap;
  }}
  .toc-link:hover {{ color: var(--text); border-color: var(--blue); text-decoration: none; }}
  .stat-row {{
    display: flex;
    gap: 1px;
    margin: 1.75rem 0;
    background: var(--panel-border);
    border-radius: 6px;
    overflow: hidden;
  }}
  .stat {{
    flex: 1;
    background: var(--panel);
    padding: 1rem 1.25rem;
  }}
  .stat-num {{ font-size: 1.8rem; font-weight: 600; font-family: var(--mono); }}
  .stat-label {{ font-size: 0.8rem; color: var(--text-dim); margin-top: 0.2rem; }}
  section {{ margin-bottom: 1.5rem; scroll-margin-top: 4.5rem; }}
  h2.section-header {{
    font-size: 0.95rem;
    font-weight: 600;
    color: var(--text);
    margin: 0 0 0.9rem;
    padding-bottom: 0.6rem;
    border-bottom: 1px solid var(--panel-border);
    cursor: pointer;
    user-select: none;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }}
  h2.section-header:hover {{ color: var(--blue); }}
  .chevron {{ display: inline-block; transition: transform 0.15s; font-size: 0.8rem; }}
  .chevron.collapsed {{ transform: rotate(-90deg); }}
  .section-body {{ overflow: hidden; }}
  .section-body.collapsed {{ display: none; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
  th {{
    text-align: left; padding: 0.5rem; font-size: 0.75rem; text-transform: uppercase;
    letter-spacing: 0.03em; color: var(--text-dim); border-bottom: 1px solid var(--panel-border);
    position: sticky; top: 0; background: var(--panel);
  }}
  th.sortable {{ cursor: pointer; user-select: none; }}
  th.sortable:hover {{ color: var(--text); }}
  .sort-arrow::after {{ content: "⇅"; opacity: 0.4; font-size: 0.7rem; margin-left: 0.2rem; }}
  th[data-sort-dir="asc"] .sort-arrow::after {{ content: "↑"; opacity: 1; }}
  th[data-sort-dir="desc"] .sort-arrow::after {{ content: "↓"; opacity: 1; }}
  td {{ padding: 0.55rem 0.5rem; border-bottom: 1px solid var(--panel-border); vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  a {{ color: var(--blue); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .dim {{ color: var(--text-dim); font-size: 0.82rem; white-space: nowrap; }}
  .mono {{ font-family: var(--mono); font-size: 0.83rem; }}
  .ioc-value {{ word-break: break-all; }}
  .empty {{ color: var(--text-dim); font-style: italic; padding: 1rem 0.5rem; }}
  .badge {{
    display: inline-block;
    padding: 0.15rem 0.55rem;
    border-radius: 3px;
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }}
  .badge-high {{ background: rgba(232,163,61,0.15); color: var(--amber); }}
  .badge-critical {{ background: rgba(217,83,79,0.18); color: var(--red); }}
  .badge-full-text {{ background: rgba(91,141,214,0.15); color: var(--blue); }}
  .bar-row {{ display: flex; align-items: center; gap: 0.8rem; margin-bottom: 0.5rem; font-size: 0.85rem; cursor: pointer; padding: 0.15rem; border-radius: 4px; }}
  .bar-row:hover {{ background: var(--panel); }}
  .bar-label {{ width: 90px; flex-shrink: 0; color: var(--text-dim); font-family: var(--mono); }}
  .bar-track {{ flex: 1; background: var(--panel-border); border-radius: 3px; height: 8px; overflow: hidden; }}
  .bar-fill {{ background: var(--amber); height: 100%; }}
  .bar-count {{ width: 45px; text-align: right; font-family: var(--mono); color: var(--text-dim); font-size: 0.8rem; }}
  .legend {{ display: flex; gap: 1.25rem; margin-top: 0.6rem; font-size: 0.8rem; color: var(--text-dim); }}
  .legend-item {{ display: flex; align-items: center; }}
  .legend-dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 0.4rem; }}
  .chart-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }}
  .chart-panel {{ background: var(--panel); border: 1px solid var(--panel-border); border-radius: 6px; padding: 1rem; }}
  .chart-title {{ font-size: 0.8rem; color: var(--text-dim); margin-bottom: 0.5rem; }}
  .chart-point {{ cursor: crosshair; }}
  @media (max-width: 700px) {{ .chart-grid {{ grid-template-columns: 1fr; }} }}
  select, input[type="search"] {{
    background: var(--panel);
    border: 1px solid var(--panel-border);
    color: var(--text);
    padding: 0.4rem 0.6rem;
    border-radius: 4px;
    font-size: 0.85rem;
    font-family: var(--sans);
  }}
  .controls {{ display: flex; gap: 0.6rem; margin-bottom: 0.9rem; }}
  .table-scroll {{ max-height: 480px; overflow-y: auto; border: 1px solid var(--panel-border); border-radius: 6px; }}
  .table-scroll table {{ font-size: 0.85rem; }}
  .table-scroll td:first-child {{ padding-left: 0.9rem; }}
  footer {{ color: var(--text-dim); font-size: 0.78rem; margin-top: 3rem; }}
  .world-map-container {{ width: 100%; }}
  .map-toolbar {{ margin-bottom: 0.75rem; }}
  .map-download-btn {{
    background: var(--panel);
    border: 1px solid var(--panel-border);
    color: var(--text);
    padding: 0.5rem 0.9rem;
    border-radius: 5px;
    font-size: 0.82rem;
    font-family: var(--sans);
    cursor: pointer;
  }}
  .map-download-btn:hover {{ background: var(--panel-border); }}
  .map-details-panel {{
    margin-top: 0.9rem;
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: 6px;
    padding: 1rem 1.2rem;
    font-size: 0.85rem;
  }}
  .map-details-header {{ font-weight: 600; margin-bottom: 0.6rem; }}
  .map-details-list {{ margin: 0; padding-left: 1.2rem; max-height: 220px; overflow-y: auto; }}
  .map-details-list li {{ margin-bottom: 0.3rem; color: var(--text); }}
  .attack-category {{
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: 6px;
    padding: 0.9rem 1.1rem;
    margin-bottom: 0.7rem;
  }}
  .attack-category-header {{
    display: flex; justify-content: space-between; align-items: baseline;
    font-weight: 600; font-size: 0.92rem; margin-bottom: 0.5rem;
  }}
  .attack-techniques {{ font-size: 0.82rem; margin-bottom: 0.4rem; }}
  .attack-techniques a {{ margin-right: 0.3rem; }}
  .attack-families {{ font-size: 0.8rem; }}
  .chart-tooltip {{
    position: absolute; display: none; background: #1c2330;
    border: 1px solid var(--panel-border); padding: 0.35rem 0.6rem;
    border-radius: 4px; font-size: 0.78rem; color: var(--text);
    pointer-events: none; z-index: 100; white-space: nowrap;
  }}
</style>
</head>
<body>
<div id="chartTooltip" class="chart-tooltip"></div>
<div class="wrap">
  <header>
    <h1>CTI-agent — instrumentpanel</h1>
    <div class="subtitle">Senast uppdaterad {generated_at} · körs automatiskt varje timme</div>
  </header>

  <nav class="toc">{toc_html}</nav>

  <div class="stat-row">
    <div class="stat"><div class="stat-num">{stats}</div><div class="stat-label">Artiklar/poster totalt</div></div>
    <div class="stat"><div class="stat-num">{ioc_stats}</div><div class="stat-label">IOCs totalt</div></div>
    <div class="stat"><div class="stat-num">{len(ransomware_victims)}</div><div class="stat-label">Senaste ransomware-offer</div></div>
    <div class="stat"><div class="stat-num">{len(high_severity)}</div><div class="stat-label">High/critical (LLM)</div></div>
    <div class="stat"><div class="stat-num">{full_text_count}</div><div class="stat-label">Artiklar med fulltext hämtad</div></div>
  </div>

  {sections_html}

  <footer>Genererad av cti-agent. Data från RSS-källor, ThreatFox (abuse.ch), Telegram och ransomware.live.</footer>
</div>

<script>
// --- Ihopfällbara sektioner ---
function toggleSection(id) {{
  document.getElementById(id + '-body').classList.toggle('collapsed');
  document.getElementById(id + '-chevron').classList.toggle('collapsed');
}}

// --- Generisk tabellsortering ---
function sortTable(tableId, colIndex, type) {{
  const table = document.getElementById(tableId);
  const tbody = table.querySelector('tbody');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  const headers = table.querySelectorAll('th');
  const header = headers[colIndex];
  const asc = header.getAttribute('data-sort-dir') !== 'asc';
  headers.forEach(th => th.removeAttribute('data-sort-dir'));
  header.setAttribute('data-sort-dir', asc ? 'asc' : 'desc');

  rows.sort((a, b) => {{
    const aCell = a.children[colIndex];
    const bCell = b.children[colIndex];
    let av = aCell ? (aCell.getAttribute('data-sort') ?? aCell.textContent.trim()) : '';
    let bv = bCell ? (bCell.getAttribute('data-sort') ?? bCell.textContent.trim()) : '';
    if (type === 'number') {{
      av = parseFloat(av) || 0;
      bv = parseFloat(bv) || 0;
      return asc ? av - bv : bv - av;
    }}
    return asc ? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av));
  }});
  rows.forEach(r => tbody.appendChild(r));
}}

// --- Generisk tabellsökning (enkla tabeller utan typfilter) ---
function filterTable(inputId, tableId) {{
  const search = document.getElementById(inputId).value.toLowerCase();
  document.querySelectorAll('#' + tableId + ' tbody tr').forEach(row => {{
    row.style.display = row.textContent.toLowerCase().includes(search) ? '' : 'none';
  }});
}}

// --- IOC-tabellens kombinerade typ+sök-filter ---
function filterIocs() {{
  const type = document.getElementById('typeFilter').value.toLowerCase();
  const search = document.getElementById('iocSearch').value.toLowerCase();
  const rows = document.querySelectorAll('#iocTable tbody tr[data-type]');
  rows.forEach(row => {{
    const rowType = row.getAttribute('data-type').toLowerCase();
    const text = row.textContent.toLowerCase();
    const matchesType = !type || rowType === type;
    const matchesSearch = !search || text.includes(search);
    row.style.display = (matchesType && matchesSearch) ? '' : 'none';
  }});
}}

// Klick på en stapel i IOC-typ-diagrammet filtrerar direkt och hoppar till listan
function filterIocsByType(type) {{
  document.getElementById('typeFilter').value = type;
  filterIocs();
  document.getElementById('sec-iocs').scrollIntoView({{behavior: 'smooth', block: 'start'}});
}}

// --- Hover-tooltips på trendgraferna ---
(function() {{
  const tooltip = document.getElementById('chartTooltip');
  document.addEventListener('mouseover', e => {{
    if (e.target.classList && e.target.classList.contains('chart-point')) {{
      tooltip.textContent = e.target.getAttribute('data-tooltip');
      tooltip.style.display = 'block';
    }}
  }});
  document.addEventListener('mousemove', e => {{
    if (e.target.classList && e.target.classList.contains('chart-point')) {{
      tooltip.style.left = (e.pageX + 12) + 'px';
      tooltip.style.top = (e.pageY - 28) + 'px';
    }}
  }});
  document.addEventListener('mouseout', e => {{
    if (e.target.classList && e.target.classList.contains('chart-point')) {{
      tooltip.style.display = 'none';
    }}
  }});
}})();
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_doc)

    print(f"    Dashboard skriven till {output_path}")


if __name__ == "__main__":
    generate_report()
