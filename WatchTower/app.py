import os
import json
import csv
import io
import sqlite3
from datetime import datetime
from flask import Flask, request, send_file, render_template_string

# SETUP:
# app - Flask app instance
# DB_PATH - string, "watchtower.db"
app = Flask(__name__)
DB_PATH = "watchtower.db"


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tool TEXT NOT NULL,
                        "check" TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        message TEXT NOT NULL,
                        source_file TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)


def import_json_report(tool_name: str, file_path: str) -> int:
    if not os.path.exists(file_path):
        return 0

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            findings = json.load(f)
    except (json.JSONDecodeError, OSError):
        return 0

    if not isinstance(findings, list):
        return 0

    now = datetime.now().isoformat()
    rows = [
        (
            tool_name,
            item.get("check", "unknown"),
            item.get("severity", "info"),
            item.get("message", ""),
            file_path,
            now,
        )
        for item in findings
        if isinstance(item, dict)
    ]

    with sqlite3.connect(DB_PATH) as conn:
        conn.executemany(
            'INSERT INTO alerts (tool, "check", severity, message, source_file,'
            " created_at) VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )

    return len(rows)


def get_alerts(search_term: str | None = None) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    if search_term:
        pattern = f"%{search_term}%"
        rows = conn.execute(
            """
            SELECT * FROM alerts
            WHERE tool LIKE ? OR "check" LIKE ? OR severity LIKE ? OR message LIKE ?
            ORDER BY id DESC
            """,
            (pattern, pattern, pattern, pattern),
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()

    conn.close()
    return [dict(row) for row in rows]


def get_stats() -> dict[str, int]:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("""
        SELECT
            COUNT(*),
            COALESCE(SUM(UPPER(severity) = 'HIGH'), 0),
            COALESCE(SUM(UPPER(severity) = 'MEDIUM'), 0),
            COALESCE(SUM(UPPER(severity) = 'LOW'), 0),
            COALESCE(SUM(UPPER(severity) = 'INFO'), 0)
        FROM alerts
    """).fetchone()
    conn.close()

    return {
        "total": row[0],
        "high": row[1],
        "medium": row[2],
        "low": row[3],
        "info": row[4],
    }


HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
  <title>Watchtower Dashboard</title>
  <style>
    body { font-family: sans-serif; margin: 2rem; background: #f8f9fa; }
    .cards { display: flex; gap: 1rem; margin-bottom: 1.5rem; }
    .card { background: #fff; padding: 1rem; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); flex: 1; text-align: center; }
    .toolbar { display: flex; justify-content: space-between; margin-bottom: 1rem; gap: 1rem; flex-wrap: wrap; }
    table { width: 100%; border-collapse: collapse; background: #fff; }
    th, td { padding: 0.75rem; border: 1px solid #dee2e6; text-align: left; }
    th { background: #343a40; color: #fff; }
  </style>
</head>
<body>
  <h1>Watchtower Alerts</h1>

  <div class="cards">
    <div class="card"><strong>Total</strong><br>{{ stats.total }}</div>
    <div class="card"><strong>High</strong><br>{{ stats.high }}</div>
    <div class="card"><strong>Medium</strong><br>{{ stats.medium }}</div>
    <div class="card"><strong>Low</strong><br>{{ stats.low }}</div>
    <div class="card"><strong>Info</strong><br>{{ stats.info }}</div>
  </div>

  <div class="toolbar">
    <form method="get" action="/">
      <input type="text" name="q" value="{{ search_term or '' }}" placeholder="Search alerts...">
      <button type="submit">Search</button>
      {% if search_term %}<a href="/">Clear</a>{% endif %}
    </form>

    <div>
      <form method="post" action="/import" style="display:inline;">
  <button type="submit" name="tool" value="LogSentinel Pro">Import LogSentinel</button>
  <button type="submit" name="tool" value="WebHawk">Import WebHawk</button>
  <button type="submit" name="tool" value="HashHound">Import HashHound</button>
  <button type="submit" name="tool" value="PacketLens">Import PacketLens</button>
</form>
      <a href="/export?q={{ search_term or '' }}">Export CSV</a>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>ID</th><th>Tool</th><th>Check</th><th>Severity</th><th>Message</th><th>Source</th><th>Created At</th>
      </tr>
    </thead>
    <tbody>
      {% for a in alerts %}
      <tr>
        <td>{{ a.id }}</td>
        <td>{{ a.tool }}</td>
        <td>{{ a.check }}</td>
        <td>{{ a.severity }}</td>
        <td>{{ a.message }}</td>
        <td>{{ a.source_file }}</td>
        <td>{{ a.created_at }}</td>
      </tr>
      {% else %}
      <tr><td colspan="7">No alerts found.</td></tr>
      {% endfor %}
    </tbody>
  </table>
</body>
</html>
"""


@app.route("/")
def index():
    search_term = request.args.get("q")
    alerts = get_alerts(search_term)
    stats = get_stats()
    return render_template_string(
        HTML_TEMPLATE, alerts=alerts, stats=stats, search_term=search_term
    )


TOOL_MAP = {
    "LogSentinel Pro": ("LogSentinel Pro", "alerts.json"),
    "WebHawk": ("WebHawk", "web_report.json"),
    "HashHound": ("HashHound", "hash_report.json"),
    "PacketLens": ("PacketLens", "packet_report.json"),
}


@app.route("/import", methods=["POST"])
def import_tool():
    tool_name = request.form.get("tool")
    tool_info = TOOL_MAP.get(tool_name)
    if not tool_info:
        return 'Unknown tool. <a href="/">Back to dashboard</a>', 404

    display_name, file_path = tool_info
    count = import_json_report(display_name, file_path)
    return f'<p>Imported {count} alerts from {display_name}.</p><a href="/">Back to dashboard</a>'


@app.route("/export")
def export_csv():
    search_term = request.args.get("q")
    alerts = get_alerts(search_term)

    output = io.StringIO()
    fields = [
        "id",
        "tool",
        "check",
        "severity",
        "message",
        "source_file",
        "created_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows(alerts)

    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    return send_file(
        mem,
        mimetype="text/csv",
        as_attachment=True,
        download_name="watchtower_export.csv",
    )


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
