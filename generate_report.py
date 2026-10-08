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
from watchlist import WATCHLIST
from daily_briefing import build_briefing
from sector_watch import (
    classify_sector, WATCHED_SECTORS, is_nordic_country, is_nordic_article,
)

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
    Interaktiv världskarta (D3 + world-atlas TopoJSON via CDN) med:
      - zoom/panorering (dra, +/- knappar, Ctrl+scrollhjul, pinch på touch)
      - förvalda vyer: Världen / Europa / Norden
      - rankad landslista bredvid kartan (klick = zooma till landet + visa offer)
      - bubblor som behåller läsbar storlek vid zoom, etiketter som visas
        gradvis (största först) för att undvika röra
      - klick på bubbla = detaljpanel, samt PNG-export av aktuell vy
    """
    if not country_counts:
        return '<p class="empty">Ingen geografisk data ännu.</p>'

    nordic = {"SE", "NO", "DK", "FI", "IS"}
    data_points = [
        {
            "country": c["country"], "n": c["n"],
            "lat": COUNTRY_CENTROIDS[c["country"]][0],
            "lon": COUNTRY_CENTROIDS[c["country"]][1],
            "nordic": c["country"] in nordic,
            "victims": victim_details.get(c["country"], []),
        }
        for c in country_counts if c["country"] in COUNTRY_CENTROIDS
    ]
    data_points.sort(key=lambda d: -d["n"])
    for rank, d in enumerate(data_points):
        d["rank"] = rank
    unplotted = [c for c in country_counts if c["country"] not in COUNTRY_CENTROIDS]
    data_json = json.dumps(data_points, ensure_ascii=False).replace("</", "<\\/")

    max_n = max((d["n"] for d in data_points), default=1)
    list_rows = "".join(
        f'''<div class="map-rank-row" data-country="{_esc(d["country"])}" onclick="mapFocus_{element_id}('{_esc(d["country"])}')">
              <span class="map-rank-code">{_esc(d["country"])}{' <span class="nordic-badge">Norden</span>' if d["nordic"] else ''}</span>
              <span class="map-rank-bar"><span style="width:{max(4, d["n"] / max_n * 100):.0f}%"></span></span>
              <span class="map-rank-n">{d["n"]}</span>
            </div>'''
        for d in data_points
    )

    unplotted_note = ""
    if unplotted:
        listed = ", ".join(f'{_esc(c["country"])} ({c["n"]})' for c in unplotted)
        unplotted_note = f'<p class="dim" style="margin-top:0.6rem;">Utanför kartans landslista: {listed}</p>'

    return f"""
    <div class="map-toolbar">
      <button class="map-btn map-view-btn active" data-view="world">Världen</button>
      <button class="map-btn map-view-btn" data-view="europe">Europa</button>
      <button class="map-btn map-view-btn" data-view="nordic">Norden</button>
      <span class="map-toolbar-sep"></span>
      <button class="map-btn" id="{element_id}ZoomIn" title="Zooma in">＋</button>
      <button class="map-btn" id="{element_id}ZoomOut" title="Zooma ut">－</button>
      <button class="map-btn" id="{element_id}Reset" title="Återställ">⟲</button>
      <span class="map-toolbar-sep"></span>
      <button onclick="downloadMapAsPng()" class="map-btn">⬇ PNG</button>
      <span class="dim map-hint">Dra för att panorera · Ctrl + scrollhjul för att zooma</span>
    </div>
    <div class="map-layout">
      <div class="map-main">
        <div id="{element_id}" class="world-map-container"></div>
      </div>
      <div class="map-rank-list">
        <div class="map-rank-title">Länder (flest offer först)</div>
        {list_rows}
      </div>
    </div>
    <div id="{element_id}Details" class="map-details-panel">
      <span class="dim">Klicka på en bubbla eller ett land i listan för att se vilka offer/grupper som ligger bakom siffran.</span>
    </div>
    {unplotted_note}
    <script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/topojson/3.0.2/topojson.min.js"></script>
    <script>
    (function() {{
      const victimData = {data_json};
      const container = document.getElementById("{element_id}");
      const width = container.clientWidth || 800;
      const height = Math.round(width * 0.56);

      const svg = d3.select(container).append("svg")
        .attr("viewBox", `0 0 ${{width}} ${{height}}`)
        .attr("width", "100%")
        .attr("height", height)
        .style("background", "#0a0d13")
        .style("border-radius", "8px")
        .style("cursor", "grab");

      const viewport = svg.append("g");
      const projection = d3.geoNaturalEarth1();
      const path = d3.geoPath(projection);

      const BOXES = {{
        europe: [[-12, 34], [40, 71]],
        nordic: [[3, 54.5], [32, 71.5]]
      }};
      let currentK = 1;
      let bubbles = null, radius = null;
      let selectedCountry = null;

      const zoom = d3.zoom()
        .scaleExtent([1, 40])
        .translateExtent([[-width * 0.2, -height * 0.2], [width * 1.2, height * 1.2]])
        .filter(event => event.type === "wheel" ? (event.ctrlKey || event.metaKey) : !event.button)
        .on("zoom", event => {{
          viewport.attr("transform", event.transform);
          currentK = event.transform.k;
          updateBubbleScale();
        }});
      svg.call(zoom);

      function updateBubbleScale() {{
        if (!bubbles) return;
        const k = currentK;
        bubbles.attr("transform", d => `translate(${{d.x}},${{d.y}}) scale(${{Math.pow(k, -0.9)}})`);
        // Visa fler etiketter ju mer man zoomar in; största länderna först.
        const maxLabels = Math.round(5 + (k - 1) * 6);
        bubbles.select("text").attr("display", d =>
          (d.rank < maxLabels || d.country === selectedCountry) ? null : "none");
        viewport.selectAll("path.country").attr("stroke-width", 0.6 / k);
      }}

      function viewTransform(box) {{
        const [[x0, y0], [x1, y1]] = [projection(box[0]), projection(box[1])];
        const minX = Math.min(x0, x1), maxX = Math.max(x0, x1);
        const minY = Math.min(y0, y1), maxY = Math.max(y0, y1);
        const k = Math.min(40, 0.9 / Math.max((maxX - minX) / width, (maxY - minY) / height));
        const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;
        return d3.zoomIdentity.translate(width / 2 - k * cx, height / 2 - k * cy).scale(k);
      }}

      function goTo(transform) {{
        svg.transition().duration(700).call(zoom.transform, transform);
      }}

      function setActiveView(name) {{
        document.querySelectorAll(".map-view-btn").forEach(b =>
          b.classList.toggle("active", b.dataset.view === name));
      }}

      function showDetails(d) {{
        selectedCountry = d.country;
        bubbles.select("circle.bubble-main").attr("stroke-width", x => x.country === d.country ? 3 : 1);
        document.querySelectorAll(".map-rank-row").forEach(r =>
          r.classList.toggle("selected", r.dataset.country === d.country));
        const panel = document.getElementById("{element_id}Details");
        const victimList = d.victims.map(v =>
          `<li><strong>${{v.group}}</strong> → ${{v.victim}}</li>`
        ).join("");
        panel.innerHTML = `
          <div class="map-details-header">${{d.country}} — ${{d.n}} rapporterade offer</div>
          <ul class="map-details-list">${{victimList || "<li>Ingen detaljerad offerinfo sparad ännu.</li>"}}</ul>
        `;
        updateBubbleScale();
      }}

      window["mapFocus_{element_id}"] = function(code) {{
        const d = victimData.find(x => x.country === code);
        if (!d || !bubbles) return;
        showDetails(d);
        const k = Math.max(currentK, 5);
        goTo(d3.zoomIdentity.translate(width / 2 - k * d.x, height / 2 - k * d.y).scale(k));
        setActiveView("");
      }};

      d3.json("https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json").then(world => {{
        const countries = topojson.feature(world, world.objects.countries);
        projection.fitSize([width, height], countries);

        viewport.append("g").selectAll("path")
          .data(countries.features)
          .join("path")
          .attr("class", "country")
          .attr("d", path)
          .attr("fill", "#1c2433")
          .attr("stroke", "#2e3646")
          .attr("stroke-width", 0.6);

        victimData.forEach(d => {{
          const p = projection([d.lon, d.lat]);
          d.x = p[0]; d.y = p[1];
        }});

        const maxN = d3.max(victimData, d => d.n) || 1;
        radius = d3.scalePow().exponent(0.5).domain([0, maxN]).range([4, 22]);
        const color = d3.scaleLinear().domain([0, maxN]).range(["#e8a33d", "#d9534f"]);

        // Ritas minsta först så att stora bubblor inte döljer små
        const drawOrder = victimData.slice().sort((a, b) => b.n - a.n);

        bubbles = viewport.append("g").selectAll("g")
          .data(drawOrder)
          .join("g")
          .style("cursor", "pointer")
          .on("click", (event, d) => {{ event.stopPropagation(); showDetails(d); }});

        bubbles.append("title").text(d => `${{d.country}}: ${{d.n}} offer`);

        bubbles.append("circle")
          .attr("class", "bubble-main")
          .attr("r", d => radius(d.n))
          .attr("fill", d => color(d.n))
          .attr("fill-opacity", 0.72)
          .attr("stroke", d => d.nordic ? "#ffffff" : color(d.n))
          .attr("stroke-width", 1);

        bubbles.append("text")
          .text(d => `${{d.country}} ${{d.n}}`)
          .attr("y", d => -radius(d.n) - 5)
          .attr("text-anchor", "middle")
          .attr("font-size", 11)
          .attr("font-weight", 600)
          .attr("fill", "#e8ecf2")
          .attr("style", "paint-order: stroke; stroke: #0a0d13; stroke-width: 3px; pointer-events: none;");

        // Ritordning: stora först i data -> reverse så små hamnar överst
        bubbles.order();
        bubbles.sort((a, b) => b.n - a.n);

        updateBubbleScale();

        document.querySelectorAll(".map-view-btn").forEach(btn => {{
          btn.addEventListener("click", () => {{
            const v = btn.dataset.view;
            setActiveView(v);
            goTo(v === "world" ? d3.zoomIdentity : viewTransform(BOXES[v]));
          }});
        }});
        document.getElementById("{element_id}ZoomIn").addEventListener("click", () =>
          svg.transition().duration(300).call(zoom.scaleBy, 1.6));
        document.getElementById("{element_id}ZoomOut").addEventListener("click", () =>
          svg.transition().duration(300).call(zoom.scaleBy, 1 / 1.6));
        document.getElementById("{element_id}Reset").addEventListener("click", () => {{
          setActiveView("world");
          goTo(d3.zoomIdentity);
        }});
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
        ctx.drawImage(img, 0, 0, svgEl.clientWidth, svgEl.clientHeight);
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

    # Sektorbevakning: matcha ransomware-offer (har redan ett sektorfält
    # från ransomware.live) och RSS/Telegram-artiklar mot bevakade sektorer.
    # Ren nyckelordsmatchning av redan insamlad data.
    sector_victim_rows = _rows(
        conn,
        """
        SELECT group_name, victim, country, sector, attack_date
        FROM ransomware_victims ORDER BY id DESC
        """,
    )
    sector_article_rows = _rows(
        conn,
        """
        SELECT title, link, feed, summary, full_text FROM articles
        WHERE feed != 'ransomware.live' AND feed NOT LIKE 'ThreatFox%'
        ORDER BY id DESC LIMIT 500
        """,
    )

    sector_matches: dict = {s: {"victims": [], "articles": []} for s in WATCHED_SECTORS}
    for v in sector_victim_rows:
        v["nordic"] = is_nordic_country(v["country"])
        # Sektorfältet OCH offernamnet (t.ex. "Port of Tanjung Pelepas")
        for sector in classify_sector(f"{v['sector'] or ''} {v['victim'] or ''}"):
            sector_matches[sector]["victims"].append(v)
    for a in sector_article_rows:
        # Fulltexten kan innehålla brus (sidomenyer m.m.), så bara början används
        text_to_check = f"{a['title']} {a['summary']} {(a['full_text'] or '')[:1500]}"
        a["nordic"] = is_nordic_article(a["feed"], text_to_check)
        for sector in classify_sector(text_to_check):
            sector_matches[sector]["articles"].append(a)

    # Nordiska träffar först inom varje sektor (stabil sortering)
    for m in sector_matches.values():
        m["victims"].sort(key=lambda x: not x["nordic"])
        m["articles"].sort(key=lambda x: not x["nordic"])

    watchlist_hit_rows = _rows(
        conn,
        """
        SELECT entry, kind, detail, source, link, first_seen
        FROM watchlist_hits ORDER BY id DESC
        """,
    )

    conn.close()

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Daglig sammanfattning — egen, kort anslutning, körs sist av allt
    # så den alltid speglar den precis uppdaterade databasen.
    briefing = build_briefing(db_path)
    briefing_html = "".join(f"<p>{_esc(line)}</p>" for line in briefing["lines"])

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

    def _render_sector_card(title: str, matches: dict, focus: bool = False, empty_text: str = "") -> str:
        victims = matches["victims"]
        articles = matches["articles"]
        nordic_count = sum(1 for x in victims + articles if x["nordic"])
        if not victims and not articles:
            items_html = f'<p class="empty">{empty_text or "Inga träffar ännu för den här sektorn."}</p>'
        else:
            item_lines = []
            for v in victims[:30]:
                flag = 1 if v["nordic"] else 0
                badge = '<span class="nordic-badge">Norden</span>' if flag else ""
                item_lines.append(
                    f'<li data-nordic="{flag}">🔴 <strong>{_esc(v["group_name"])}</strong> → '
                    f'{_esc(v["victim"])} ({_esc(v["country"])}) — ransomware-offer{badge}</li>'
                )
            for a in articles[:30]:
                flag = 1 if a["nordic"] else 0
                badge = '<span class="nordic-badge">Norden</span>' if flag else ""
                item_lines.append(
                    f'<li data-nordic="{flag}">📰 <a href="{_esc(a["link"])}" target="_blank" rel="noopener">'
                    f'{_esc(a["title"])}</a> <span class="dim">({_esc(a["feed"])})</span>{badge}</li>'
                )
            items_html = f'<ul class="sector-list">{"".join(item_lines)}</ul>'

        css_class = "attack-category sector-card focus" if focus else "attack-category sector-card"
        return f'''
          <div class="{css_class}">
            <div class="attack-category-header">
              <span>{_esc(title)}</span>
              <span class="dim">{len(victims)} offer · {len(articles)} artiklar · {nordic_count} nordiska</span>
            </div>
            {items_html}
            <p class="empty sector-empty-note" style="display:none;">Inga nordiska träffar för den här sektorn.</p>
          </div>'''

    nordic_empty_text = (
        "Inga nordiska träffar ännu. De dyker upp här när ransomware-offer från "
        "SE/NO/DK/FI/IS rapporteras, eller när nordiska källor (CERT-SE, NSM, DKCERT, "
        "NCSC-FI) eller artiklar som nämner Norden matchar sektorn."
    )

    # Två fokuskort högst upp: nordiska träffar för offentlig sektor och transport
    focus_specs = [
        ("Norden — offentlig sektor", "Offentlig sektor"),
        ("Norden — transport & logistik", "Transport & logistik"),
    ]
    sector_html_parts = []
    for focus_title, base_sector in focus_specs:
        base = sector_matches.get(base_sector)
        if base is None:
            continue
        nordic_subset = {
            "victims": [v for v in base["victims"] if v["nordic"]],
            "articles": [a for a in base["articles"] if a["nordic"]],
        }
        sector_html_parts.append(
            _render_sector_card(focus_title, nordic_subset, focus=True, empty_text=nordic_empty_text)
        )

    # Därefter alla bevakade sektorer globalt (nordiska träffar märkta och först)
    sector_html_parts.append('<div class="sector-divider dim">Alla sektorer — globalt (nordiska träffar märkta och först)</div>')
    for sector, matches in sector_matches.items():
        sector_html_parts.append(_render_sector_card(sector, matches))

    sector_controls = (
        '<div class="controls"><label class="nordic-toggle">'
        '<input type="checkbox" id="nordicOnly" onchange="applyNordicFilter()"> '
        'Visa bara Norden (SE, NO, DK, FI, IS) i alla sektorer</label></div>'
    )
    sector_html = sector_controls + "".join(sector_html_parts)

    # --- Bevakningslista: ett kort per bevakad organisation ---
    kind_meta = {
        "ioc_domain": ("🚨", "Domän listad som IOC", "critical"),
        "ransomware": ("🔴", "Ransomware-offer", "critical"),
        "lookalike": ("🎭", "Möjlig imitation", "high"),
        "article": ("📰", "Omnämnd i artikel/Telegram", "info"),
    }
    kind_order = ["ioc_domain", "ransomware", "lookalike", "article"]

    hits_by_entry: dict = {}
    for row in watchlist_hit_rows:
        hits_by_entry.setdefault(row["entry"], []).append(row)

    watch_cards = []
    total_watch_hits = 0
    for entry in WATCHLIST:
        rows = hits_by_entry.get(entry["name"], [])
        total_watch_hits += len(rows)
        watched_what = ", ".join(entry.get("domains", []) + entry.get("terms", []))
        if not rows:
            body = '<p class="empty">Inga träffar — bra. Bevakar: ' + _esc(watched_what) + "</p>"
        else:
            rows_sorted = sorted(
                rows, key=lambda r: kind_order.index(r["kind"]) if r["kind"] in kind_order else 99
            )
            lines = []
            for r in rows_sorted[:60]:
                icon, label, level = kind_meta.get(r["kind"], ("•", r["kind"], "info"))
                detail = _esc(r["detail"])
                if r["link"]:
                    detail = f'<a href="{_esc(r["link"])}" target="_blank" rel="noopener">{detail}</a>'
                lines.append(
                    f'<li>{icon} <span class="watch-kind watch-{level}">{_esc(label)}</span> '
                    f'{detail} <span class="dim">({_esc(r["source"])} · sedd {_esc((r["first_seen"] or "")[:10])})</span></li>'
                )
            body = f'<ul class="sector-list">{"".join(lines)}</ul>'

        crit = sum(1 for r in rows if r["kind"] in ("ioc_domain", "ransomware"))
        header_right = f'{len(rows)} träffar' + (f' · <span class="watch-critical-count">{crit} allvarliga</span>' if crit else "")
        card_class = "attack-category watch-card alert" if crit else "attack-category watch-card"
        watch_cards.append(f'''
          <div class="{card_class}">
            <div class="attack-category-header">
              <span>{_esc(entry["name"])}</span>
              <span class="dim">{header_right}</span>
            </div>
            {body}
          </div>''')

    watch_intro = (
        '<p class="dim" style="white-space:normal; margin-bottom:0.9rem;">'
        "Träffar sparas permanent och rensas aldrig. Ändra vilka organisationer och domäner "
        "som bevakas i <code>watchlist.py</code>. Imitationsjakten är medvetet bred och kan ge "
        "enstaka falska träffar.</p>"
    )
    watchlist_html = watch_intro + ("".join(watch_cards) or '<p class="empty">Bevakningslistan är tom — lägg till poster i watchlist.py.</p>')

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
        ("sec-watchlist", "Bevakningslista", watchlist_html),
        ("sec-attack", "Malware-familjer mot MITRE ATT&CK", attack_html),
        ("sec-sectors", "Sektorbevakning", sector_html),
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
  .briefing-box {{
    background: linear-gradient(135deg, rgba(91,141,214,0.08), rgba(79,179,169,0.05));
    border: 1px solid var(--panel-border);
    border-left: 3px solid var(--blue);
    border-radius: 6px;
    padding: 1rem 1.3rem;
    margin-bottom: 1.5rem;
  }}
  .briefing-title {{
    font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em;
    color: var(--text-dim); font-weight: 600; margin-bottom: 0.5rem;
  }}
  .briefing-box p {{ margin: 0.35rem 0; font-size: 0.92rem; }}
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
  .map-toolbar {{ margin-bottom: 0.75rem; display: flex; flex-wrap: wrap; align-items: center; gap: 0.4rem; }}
  .map-btn {{
    background: var(--panel);
    border: 1px solid var(--panel-border);
    color: var(--text);
    padding: 0.4rem 0.8rem;
    border-radius: 5px;
    font-size: 0.82rem;
    font-family: var(--sans);
    cursor: pointer;
  }}
  .map-btn:hover {{ background: var(--panel-border); }}
  .map-btn.active {{ border-color: var(--amber); color: var(--amber); }}
  .map-toolbar-sep {{ width: 1px; height: 1.4rem; background: var(--panel-border); margin: 0 0.3rem; }}
  .map-hint {{ margin-left: auto; font-size: 0.75rem; white-space: normal; }}
  .map-layout {{ display: grid; grid-template-columns: minmax(0, 1fr) 230px; gap: 1rem; align-items: start; }}
  .map-rank-list {{
    background: var(--panel); border: 1px solid var(--panel-border); border-radius: 6px;
    max-height: 460px; overflow-y: auto; padding: 0.4rem 0;
  }}
  .map-rank-title {{ font-size: 0.75rem; color: var(--text-dim); padding: 0.3rem 0.8rem 0.5rem; }}
  .map-rank-row {{
    display: grid; grid-template-columns: 62px 1fr 28px; gap: 0.5rem; align-items: center;
    padding: 0.3rem 0.8rem; cursor: pointer; font-size: 0.82rem;
  }}
  .map-rank-row:hover {{ background: var(--panel-border); }}
  .map-rank-row.selected {{ background: rgba(232,163,61,0.15); }}
  .map-rank-code {{ font-family: var(--mono); }}
  .map-rank-bar {{ background: var(--panel-border); border-radius: 3px; height: 6px; overflow: hidden; }}
  .map-rank-bar span {{ display: block; height: 100%; background: var(--amber); }}
  .map-rank-n {{ text-align: right; font-family: var(--mono); color: var(--text-dim); font-size: 0.78rem; }}
  @media (max-width: 800px) {{ .map-layout {{ grid-template-columns: 1fr; }} .map-rank-list {{ max-height: 240px; }} }}
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
  .sector-list {{ list-style: none; margin: 0; padding: 0; font-size: 0.85rem; max-height: 260px; overflow-y: auto; }}
  .sector-list li {{ margin-bottom: 0.4rem; }}
  .sector-card.focus {{ border-color: #4fb3a9; border-left-width: 3px; }}
  .sector-divider {{ margin: 1.2rem 0 0.7rem; padding-top: 0.9rem; border-top: 1px solid var(--panel-border); }}
  .nordic-badge {{
    display: inline-block; margin-left: 0.5rem; padding: 0.05rem 0.45rem;
    font-size: 0.68rem; font-weight: 600; border-radius: 3px;
    background: rgba(79,179,169,0.15); color: #4fb3a9;
  }}
  .nordic-toggle {{ display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; cursor: pointer; }}
  .watch-card.alert {{ border-color: var(--red); border-left-width: 3px; }}
  .watch-kind {{ font-size: 0.7rem; font-weight: 600; padding: 0.05rem 0.45rem; border-radius: 3px; margin-right: 0.3rem; }}
  .watch-critical {{ background: rgba(217,83,79,0.18); color: var(--red); }}
  .watch-high {{ background: rgba(232,163,61,0.15); color: var(--amber); }}
  .watch-info {{ background: rgba(91,141,214,0.15); color: var(--blue); }}
  .watch-critical-count {{ color: var(--red); font-weight: 600; }}
  code {{ font-family: var(--mono); background: var(--panel-border); padding: 0.05rem 0.35rem; border-radius: 3px; font-size: 0.8rem; }}
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

  <div class="briefing-box">
    <div class="briefing-title">Senaste dygnet</div>
    {briefing_html}
  </div>

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

// --- Norden-brytare i sektorbevakningen ---
function applyNordicFilter() {{
  const only = document.getElementById('nordicOnly').checked;
  document.querySelectorAll('.sector-card').forEach(card => {{
    let visible = 0;
    card.querySelectorAll('li[data-nordic]').forEach(li => {{
      const show = !only || li.getAttribute('data-nordic') === '1';
      li.style.display = show ? '' : 'none';
      if (show) visible++;
    }});
    const note = card.querySelector('.sector-empty-note');
    if (note) note.style.display = (only && visible === 0) ? '' : 'none';
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
