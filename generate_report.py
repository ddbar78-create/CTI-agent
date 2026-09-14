"""
Genererar index.html — en fristående instrumentpanel över allt agenten
samlat in. Ingen server, inget ramverk, bara en enda HTML-fil med
inbäddad CSS/JS, byggd direkt ur cti.db.

Körs som sista steg i agent.py. Committas till repot av GitHub Actions
precis som cti.db, och kan publiceras gratis via GitHub Pages
(Settings -> Pages -> Deploy from branch -> main / root).
"""

import html
import sqlite3
from datetime import datetime, timezone

from storage import DB_PATH

OUTPUT_PATH = "index.html"


def _rows(conn, query, params=()):
    cur = conn.cursor()
    cur.execute(query, params)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def _esc(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def _svg_trend_chart(dates: list, series: dict, width: int = 1000, height: int = 200) -> str:
    """
    Bygger en enkel, beroendefri SVG-linjegraf.
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

    for values, color in series.values():
        points = " ".join(f"{px(i):.1f},{py(v):.1f}" for i, v in enumerate(values))
        parts.append(f'<polyline fill="none" stroke="{color}" stroke-width="2" points="{points}" />')
        for i, v in enumerate(values):
            if v:
                parts.append(f'<circle cx="{px(i):.1f}" cy="{py(v):.1f}" r="2.5" fill="{color}" />')

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
        SELECT feed, title, link, published, fetched_at
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

    conn.close()

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # --- Bygg HTML ---
    breakdown_html = "\n".join(
        f'''<div class="bar-row">
              <span class="bar-label">{_esc(r["ioc_type"])}</span>
              <div class="bar-track"><div class="bar-fill" style="width:{max(4, r["n"] / max_type_count * 100):.0f}%"></div></div>
              <span class="bar-count">{r["n"]}</span>
            </div>'''
        for r in ioc_type_breakdown
    )

    victims_html = "\n".join(
        f'''<tr>
              <td>{_esc(v["title"])}</td>
              <td class="dim">{_esc(v["published"] or v["fetched_at"])[:10]}</td>
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
            </tr>'''
        for a in recent_articles
    ) or '<tr><td colspan="2" class="empty">Inga artiklar ännu.</td></tr>'

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
  header {{ margin-bottom: 2.5rem; }}
  h1 {{
    font-size: 1.5rem;
    font-weight: 600;
    margin: 0 0 0.3rem;
    letter-spacing: -0.01em;
  }}
  .subtitle {{ color: var(--text-dim); font-size: 0.9rem; }}
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
  section {{ margin-bottom: 2.5rem; }}
  h2 {{
    font-size: 0.95rem;
    font-weight: 600;
    color: var(--text);
    margin: 0 0 0.9rem;
    padding-bottom: 0.6rem;
    border-bottom: 1px solid var(--panel-border);
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
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
  .bar-row {{ display: flex; align-items: center; gap: 0.8rem; margin-bottom: 0.5rem; font-size: 0.85rem; }}
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
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>CTI-agent — instrumentpanel</h1>
    <div class="subtitle">Senast uppdaterad {generated_at} · körs automatiskt varje timme</div>
  </header>

  <div class="stat-row">
    <div class="stat"><div class="stat-num">{stats}</div><div class="stat-label">Artiklar/poster totalt</div></div>
    <div class="stat"><div class="stat-num">{ioc_stats}</div><div class="stat-label">IOCs totalt</div></div>
    <div class="stat"><div class="stat-num">{len(ransomware_victims)}</div><div class="stat-label">Senaste ransomware-offer</div></div>
    <div class="stat"><div class="stat-num">{len(high_severity)}</div><div class="stat-label">High/critical (LLM)</div></div>
  </div>

  <section>
    <h2>Trend, senaste {len(daily_rows)} dagarna</h2>
    <div class="chart-grid">
      <div class="chart-panel">
        <div class="chart-title">ThreatFox (hög volym)</div>
        {threatfox_chart_html}
      </div>
      <div class="chart-panel">
        <div class="chart-title">Övriga källor</div>
        {other_sources_chart_html}
      </div>
    </div>
  </section>

  <section>
    <h2>IOC-typer i databasen</h2>
    {breakdown_html}
  </section>

  <section>
    <h2>Senaste ransomware-offeraviseringar</h2>
    <div class="table-scroll">
      <table>
        <tbody>{victims_html}</tbody>
      </table>
    </div>
  </section>

  <section>
    <h2>Hög/kritisk allvarlighet (LLM-flaggat)</h2>
    <div class="table-scroll">
      <table>
        <tbody>{severity_html}</tbody>
      </table>
    </div>
  </section>

  <section>
    <h2>Senaste IOCs</h2>
    <div class="controls">
      <select id="typeFilter" onchange="filterIocs()">
        <option value="">Alla typer</option>
        {filter_options}
      </select>
      <input type="search" id="iocSearch" placeholder="Sök värde..." oninput="filterIocs()">
    </div>
    <div class="table-scroll">
      <table id="iocTable">
        <tbody>{iocs_html}</tbody>
      </table>
    </div>
  </section>

  <section>
    <h2>Senaste artiklar (RSS / Telegram)</h2>
    <div class="table-scroll">
      <table>
        <tbody>{articles_html}</tbody>
      </table>
    </div>
  </section>

  <footer>Genererad av cti-agent. Data från RSS-källor, ThreatFox (abuse.ch), Telegram och ransomware.live.</footer>
</div>

<script>
function filterIocs() {{
  const type = document.getElementById('typeFilter').value.toLowerCase();
  const search = document.getElementById('iocSearch').value.toLowerCase();
  const rows = document.querySelectorAll('#iocTable tr[data-type]');
  rows.forEach(row => {{
    const rowType = row.getAttribute('data-type').toLowerCase();
    const text = row.textContent.toLowerCase();
    const matchesType = !type || rowType === type;
    const matchesSearch = !search || text.includes(search);
    row.style.display = (matchesType && matchesSearch) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_doc)

    print(f"    Dashboard skriven till {output_path}")


if __name__ == "__main__":
    generate_report()
