#!/usr/bin/env python3
"""
OFI — Dashboard Generator
===========================
Calculează statistici agregate dintr-un dataset OFI și generează:
    1. dashboard_data.json  — toate statisticile, brute (pentru API/alte unelte)
    2. dashboard.html       — dashboard static, deschis direct în browser,
                              fără build step, fără dependențe de server.

Utilizare:
    python3 dashboard_generator.py --input scams.json --outdir exports/dashboard
"""

import json
import argparse
from collections import Counter
from pathlib import Path
from datetime import datetime, timezone


def load_entries(path: Path) -> list:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def compute_statistics(entries: list) -> dict:
    n = len(entries)
    platforms = Counter(e.get("platform", "unknown") for e in entries)
    severities = Counter(e.get("severity", "unknown") for e in entries)
    tags = Counter(t for e in entries for t in e.get("tags", []))
    techniques = Counter(
        e.get("scam_dna", {}).get("technique", e.get("title", "—")) for e in entries
    )
    psychology = Counter(
        p for e in entries for p in e.get("scam_dna", {}).get("psychology", [])
    )
    payment_methods = Counter(
        p for e in entries for p in e.get("scam_dna", {}).get("payment_methods", [])
    )
    brands = Counter(
        b for e in entries for b in e.get("scam_dna", {}).get("brand_abuse", [])
    )

    ioc_counts = Counter()
    for e in entries:
        ioc = e.get("ioc", {})
        for kind in ("domains", "urls", "phones", "emails", "wallets", "usernames", "ipv4", "ipv6", "hashes"):
            ioc_counts[kind] += len(ioc.get(kind, []))

    campaigns = {}
    for e in entries:
        camp = e.get("campaign") or {}
        cid = camp.get("campaign_id")
        if cid:
            campaigns.setdefault(cid, {
                "campaign_id": cid,
                "name": camp.get("campaign_name", cid),
                "entries": [],
                "first_seen": camp.get("first_seen"),
                "last_seen": camp.get("last_seen"),
            })
            campaigns[cid]["entries"].append(e.get("id"))

    verified = sum(1 for e in entries if (e.get("verification") or {}).get("status") == "verified")
    avg_quality = (
        sum((e.get("quality") or {}).get("overall", 0) for e in entries) / n if n else 0
    )
    avg_severity_score = (
        sum(e.get("severity_score", 0) for e in entries) / n if n else 0
    )
    total_loss_median = sum(
        (e.get("scam_dna", {}).get("typical_loss_ron") or {}).get("median", 0) for e in entries
    )

    top_scams = sorted(
        entries, key=lambda e: e.get("severity_score", 0), reverse=True
    )[:10]
    top_scams_list = [
        {
            "id": e.get("id"), "title": e.get("title"),
            "severity": e.get("severity"), "severity_score": e.get("severity_score"),
            "platform": e.get("platform"),
        }
        for e in top_scams
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "totals": {
            "entries": n,
            "verified_entries": verified,
            "verification_rate": round(verified / n, 3) if n else 0,
            "campaigns": len(campaigns),
            "avg_quality_score": round(avg_quality, 3),
            "avg_severity_score": round(avg_severity_score, 2),
            "estimated_total_median_loss_ron": total_loss_median,
        },
        "top_platforms": platforms.most_common(10),
        "top_severities": severities.most_common(),
        "top_tags": tags.most_common(15),
        "top_techniques": techniques.most_common(10),
        "top_psychology_tactics": psychology.most_common(10),
        "top_payment_methods": payment_methods.most_common(10),
        "top_brands_abused": brands.most_common(10),
        "ioc_counts": dict(ioc_counts),
        "campaigns": list(campaigns.values()),
        "top_scams_by_severity": top_scams_list,
    }


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="UTF-8">
<title>Open Fraud Intelligence — Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.4/chart.umd.min.js"></script>
<style>
  :root {{
    --bg: #0f172a; --panel: #1e293b; --border: #334155;
    --text: #e2e8f0; --muted: #94a3b8; --accent: #7c3aed;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
    padding: 32px;
  }}
  h1 {{ margin: 0 0 4px; font-size: 24px; }}
  .subtitle {{ color: var(--muted); margin-bottom: 28px; font-size: 13px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 28px; }}
  .stat-card {{
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 18px 20px;
  }}
  .stat-card .value {{ font-size: 28px; font-weight: 700; color: var(--accent); }}
  .stat-card .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; margin-top: 4px; }}
  .panels {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr)); gap: 20px; }}
  .panel {{
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 20px;
  }}
  .panel h2 {{ font-size: 14px; margin: 0 0 14px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  td, th {{ padding: 6px 4px; border-bottom: 1px solid var(--border); text-align: left; }}
  th {{ color: var(--muted); font-weight: 500; }}
  .sev-Critical {{ color: #f87171; }} .sev-High {{ color: #fb923c; }}
  .sev-Medium {{ color: #38bdf8; }} .sev-Low {{ color: #4ade80; }}
  canvas {{ max-height: 260px; }}
  footer {{ color: var(--muted); font-size: 11px; margin-top: 32px; text-align: center; }}
</style>
</head>
<body>
  <h1>🛡️ Open Fraud Intelligence — Dashboard</h1>
  <div class="subtitle">Generat la {generated_at} · {n_entries} intrări analizate</div>

  <div class="grid">
    <div class="stat-card"><div class="value">{n_entries}</div><div class="label">Intrări totale</div></div>
    <div class="stat-card"><div class="value">{verification_rate}%</div><div class="label">Verificate</div></div>
    <div class="stat-card"><div class="value">{n_campaigns}</div><div class="label">Campanii detectate</div></div>
    <div class="stat-card"><div class="value">{avg_severity}</div><div class="label">Severitate medie /10</div></div>
    <div class="stat-card"><div class="value">{avg_quality}</div><div class="label">Scor calitate mediu</div></div>
  </div>

  <div class="panels">
    <div class="panel"><h2>Top platforme</h2><canvas id="chartPlatforms"></canvas></div>
    <div class="panel"><h2>Distribuție severitate</h2><canvas id="chartSeverity"></canvas></div>
    <div class="panel"><h2>Tactici psihologice folosite</h2><canvas id="chartPsychology"></canvas></div>
    <div class="panel"><h2>Metode de plată</h2><canvas id="chartPayment"></canvas></div>
    <div class="panel">
      <h2>Top fraude după severitate</h2>
      <table>
        <tr><th>ID</th><th>Titlu</th><th>Sev.</th><th>Scor</th></tr>
        {top_scams_rows}
      </table>
    </div>
    <div class="panel">
      <h2>IOC colectate</h2>
      <table>
        {ioc_rows}
      </table>
    </div>
  </div>

  <footer>Open Fraud Intelligence · dashboard generat static, fără server · sursă: dashboard_data.json</footer>

<script>
const data = {data_json};

new Chart(document.getElementById('chartPlatforms'), {{
  type: 'bar',
  data: {{
    labels: data.top_platforms.map(p => p[0]),
    datasets: [{{ label: 'Intrări', data: data.top_platforms.map(p => p[1]), backgroundColor: '#7c3aed' }}]
  }},
  options: {{ plugins: {{ legend: {{ display: false }} }}, scales: {{ y: {{ beginAtZero: true, ticks: {{ color: '#94a3b8' }} }}, x: {{ ticks: {{ color: '#94a3b8' }} }} }} }}
}});

new Chart(document.getElementById('chartSeverity'), {{
  type: 'doughnut',
  data: {{
    labels: data.top_severities.map(s => s[0]),
    datasets: [{{ data: data.top_severities.map(s => s[1]),
      backgroundColor: ['#7f1d1d','#fb923c','#38bdf8','#4ade80','#94a3b8'] }}]
  }},
  options: {{ plugins: {{ legend: {{ labels: {{ color: '#e2e8f0' }} }} }} }}
}});

new Chart(document.getElementById('chartPsychology'), {{
  type: 'bar',
  data: {{
    labels: data.top_psychology_tactics.map(p => p[0]),
    datasets: [{{ label: 'Frecvență', data: data.top_psychology_tactics.map(p => p[1]), backgroundColor: '#0891b2' }}]
  }},
  options: {{ indexAxis: 'y', plugins: {{ legend: {{ display: false }} }}, scales: {{ x: {{ ticks: {{ color: '#94a3b8' }} }}, y: {{ ticks: {{ color: '#94a3b8' }} }} }} }}
}});

new Chart(document.getElementById('chartPayment'), {{
  type: 'pie',
  data: {{
    labels: data.top_payment_methods.map(p => p[0]),
    datasets: [{{ data: data.top_payment_methods.map(p => p[1]),
      backgroundColor: ['#15803d','#7c3aed','#0891b2','#b91c1c','#f59e0b'] }}]
  }},
  options: {{ plugins: {{ legend: {{ labels: {{ color: '#e2e8f0' }} }} }} }}
}});
</script>
</body>
</html>
"""


def render_html(stats: dict) -> str:
    top_scams_rows = "\n        ".join(
        f'<tr><td>{s["id"]}</td><td>{s["title"]}</td>'
        f'<td class="sev-{s["severity"]}">{s["severity"]}</td><td>{s["severity_score"]}</td></tr>'
        for s in stats["top_scams_by_severity"]
    )
    ioc_rows = "\n        ".join(
        f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in stats["ioc_counts"].items() if v
    ) or "<tr><td colspan='2'>Niciun IOC colectat</td></tr>"

    return HTML_TEMPLATE.format(
        generated_at=stats["generated_at"][:19].replace("T", " "),
        n_entries=stats["totals"]["entries"],
        verification_rate=round(stats["totals"]["verification_rate"] * 100, 1),
        n_campaigns=stats["totals"]["campaigns"],
        avg_severity=stats["totals"]["avg_severity_score"],
        avg_quality=stats["totals"]["avg_quality_score"],
        top_scams_rows=top_scams_rows,
        ioc_rows=ioc_rows,
        data_json=json.dumps(stats, ensure_ascii=False),
    )


def main():
    parser = argparse.ArgumentParser(description="OFI Dashboard Generator")
    parser.add_argument("--input", required=True)
    parser.add_argument("--outdir", default=".")
    args = parser.parse_args()

    entries = load_entries(Path(args.input))
    stats = compute_statistics(entries)

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    data_path = outdir / "dashboard_data.json"
    html_path = outdir / "dashboard.html"

    data_path.write_text(json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8")
    html_path.write_text(render_html(stats), encoding="utf-8")

    print(f"✅ Statistici: {data_path}")
    print(f"✅ Dashboard:  {html_path}")
    print(f"   {stats['totals']['entries']} intrări, {stats['totals']['campaigns']} campanii detectate")


if __name__ == "__main__":
    main()
