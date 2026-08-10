"""
Threat Intel Dashboard — search UI + stats over the indicator index
built by ingest.py.

Run: python search_app.py, then open http://127.0.0.1:5000
"""

import csv
import io
import os
import sqlite3

from flask import Flask, Response, render_template_string, request

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
DB_PATH = os.path.join(DATA_DIR, "index.db")

app = Flask(__name__)

TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Threat Intel Dashboard</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
  <style>
    :root {
      --bg: #0d1117;
      --panel: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --accent: #58a6ff;
      --danger: #f85149;
      --muted: #8b949e;
    }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      max-width: 1000px;
      margin: 0 auto;
      padding: 24px 16px 60px;
    }
    h1 { font-size: 22px; margin-bottom: 4px; }
    .subtitle { color: var(--muted); font-size: 13px; margin-bottom: 24px; }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
    }
    .stat-value { font-size: 24px; font-weight: 700; color: var(--accent); }
    .stat-label { font-size: 12px; color: var(--muted); margin-top: 2px; }

    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 20px;
    }
    .panel h3 { margin-top: 0; font-size: 14px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }

    input[type=text] {
      width: 100%;
      padding: 10px 12px;
      font-size: 15px;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
    }
    input[type=text]:focus { outline: none; border-color: var(--accent); }

    table { width: 100%; border-collapse: collapse; margin-top: 14px; font-size: 13px; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 11px; }
    .source-urlhaus { color: var(--danger); font-weight: 600; }
    .source-feodotracker { color: var(--accent); font-weight: 600; }
    .source-threatfox { color: #d29922; font-weight: 600; }
    .indicator { word-break: break-all; font-family: monospace; font-size: 12px; }

    .export-link { font-size: 12px; color: var(--accent); text-decoration: none; }
    .export-link:hover { text-decoration: underline; }

    canvas { max-height: 220px; }
  </style>
</head>
<body>
  <h1>Threat Intel Dashboard</h1>
  <div class="subtitle">
    Live indicators from URLhaus, Feodo Tracker &amp; ThreatFox (abuse.ch public feeds)
    {% if last_ingest %} - last updated {{ last_ingest }}{% endif %}
  </div>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-value">{{ total_count }}</div>
      <div class="stat-label">Total Indicators</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{ source_counts.get('urlhaus', 0) }}</div>
      <div class="stat-label">URLhaus (URLs)</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{ source_counts.get('feodotracker', 0) }}</div>
      <div class="stat-label">Feodo Tracker (IPs)</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{ source_counts.get('threatfox', 0) }}</div>
      <div class="stat-label">ThreatFox (IOCs)</div>
    </div>
  </div>

  <div class="panel">
    <h3>Top Malware / Threat Types</h3>
    <canvas id="threatChart"></canvas>
  </div>

  <div class="panel">
    <h3>Search</h3>
    <form method="get" action="/search">
      <input type="text" name="q" value="{{ query|default('') }}" placeholder="Search by URL, IP, malware family, tag...">
    </form>
  </div>

  {% if results is defined %}
  <div class="panel">
    <h3>Results ({{ results|length }}) {% if query %}<a class="export-link" href="/export?q={{ query }}">export CSV</a>{% endif %}</h3>
    <table>
      <tr><th>Source</th><th>Indicator</th><th>Threat</th><th>Tags/Status</th><th>Date Added</th></tr>
      {% for r in results %}
      <tr>
        <td class="source-{{ r.source }}">{{ r.source }}</td>
        <td class="indicator">{{ r.indicator }}</td>
        <td>{{ r.threat_type }}</td>
        <td>{{ r.tags }}</td>
        <td>{{ r.date_added }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
  {% endif %}

  <script>
    const chartLabels = {{ top_threats_labels|tojson }};
    const chartData = {{ top_threats_values|tojson }};
    new Chart(document.getElementById('threatChart'), {
      type: 'bar',
      data: {
        labels: chartLabels,
        datasets: [{
          label: 'Indicator count',
          data: chartData,
          backgroundColor: '#58a6ff'
        }]
      },
      options: {
        indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#8b949e' }, grid: { color: '#30363d' } },
          y: { ticks: { color: '#c9d1d9' }, grid: { display: false } }
        }
      }
    });
  </script>
</body>
</html>
"""


def get_db():
    return sqlite3.connect(DB_PATH)


def get_dashboard_stats():
    conn = get_db()

    total_count = conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]

    source_counts = dict(
        conn.execute("SELECT source, COUNT(*) FROM indicators GROUP BY source").fetchall()
    )

    top_threats = conn.execute(
        """
        SELECT threat_type, COUNT(*) as c
        FROM indicators
        WHERE threat_type != ''
        GROUP BY threat_type
        ORDER BY c DESC
        LIMIT 8
        """
    ).fetchall()

    last_ingest = None
    try:
        row = conn.execute("SELECT value FROM meta WHERE key = 'last_ingest'").fetchone()
        if row:
            last_ingest = row[0]
    except sqlite3.OperationalError:
        pass

    conn.close()

    return {
        "total_count": total_count,
        "source_counts": source_counts,
        "top_threats_labels": [t[0] for t in top_threats],
        "top_threats_values": [t[1] for t in top_threats],
        "last_ingest": last_ingest,
    }


def run_search(query, limit=50):
    conn = get_db()
    cur = conn.execute(
        """
        SELECT source, indicator, threat_type, tags, date_added
        FROM indicators
        WHERE indicators MATCH ?
        ORDER BY date_added DESC
        LIMIT ?
        """,
        (query, limit),
    )
    results = [
        {
            "source": row[0],
            "indicator": row[1],
            "threat_type": row[2],
            "tags": row[3],
            "date_added": row[4],
        }
        for row in cur.fetchall()
    ]
    conn.close()
    return results


@app.route("/")
def home():
    stats = get_dashboard_stats()
    return render_template_string(TEMPLATE, **stats)


@app.route("/search")
def search():
    query = request.args.get("q", "").strip()
    stats = get_dashboard_stats()
    if not query:
        return render_template_string(TEMPLATE, results=[], query=query, **stats)

    results = run_search(query)
    return render_template_string(TEMPLATE, results=results, query=query, **stats)


@app.route("/export")
def export():
    query = request.args.get("q", "").strip()
    if not query:
        return "No query provided", 400

    results = run_search(query, limit=500)

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=["source", "indicator", "threat_type", "tags", "date_added"])
    writer.writeheader()
    writer.writerows(results)

    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=threat_intel_{query}.csv"},
    )


@app.route("/refresh")
def refresh():
    secret = request.args.get("key", "")
    expected = os.environ.get("REFRESH_KEY", "")
    if not expected or secret != expected:
        return "Forbidden", 403
    import ingest
    try:
        ingest.run()
        return "Refresh complete", 200
    except Exception as e:
        return f"Refresh failed: {e}", 500


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print("No index found yet — run ingest.py first.")
    app.run(host="127.0.0.1", port=5000, debug=False)
