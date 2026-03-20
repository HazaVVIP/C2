"""
output/reporter.py
Generates reports from scan findings in JSON, CSV, or HTML format.
"""

import json
import csv
import os
from datetime import datetime
from typing import List, Dict


class Reporter:
    def __init__(self, output_format: str = "json"):
        self.format = output_format

    def save(self, findings: List[Dict], keyword: str) -> str:
        """Save findings to file and return the output filename."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_keyword = keyword.replace("/", "_").replace(".", "_")
        filename = f"githunt_{safe_keyword}_{timestamp}.{self.format}"

        if self.format == "json":
            self._save_json(findings, filename, keyword)
        elif self.format == "csv":
            self._save_csv(findings, filename)
        elif self.format == "html":
            self._save_html(findings, filename, keyword)

        return filename

    def _save_json(self, findings: List[Dict], filename: str, keyword: str):
        report = {
            "meta": {
                "tool": "GitHunt",
                "keyword": keyword,
                "generated_at": datetime.utcnow().isoformat(),
                "total_findings": len(findings),
                "high": len([f for f in findings if f["severity"] == "HIGH"]),
                "medium": len([f for f in findings if f["severity"] == "MEDIUM"]),
                "low": len([f for f in findings if f["severity"] == "LOW"]),
            },
            "findings": findings,
        }
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)

    def _save_csv(self, findings: List[Dict], filename: str):
        if not findings:
            with open(filename, "w") as f:
                f.write("No findings.\n")
            return

        fields = ["severity", "type", "repo", "filename", "line_number",
                  "matched_value", "source_url", "timestamp"]

        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(findings)

    def _save_html(self, findings: List[Dict], filename: str, keyword: str):
        high   = [f for f in findings if f["severity"] == "HIGH"]
        medium = [f for f in findings if f["severity"] == "MEDIUM"]
        low    = [f for f in findings if f["severity"] == "LOW"]

        def row(f):
            sev = f["severity"]
            color = {"HIGH": "#ff4d4d", "MEDIUM": "#ffa64d", "LOW": "#ffff4d"}.get(sev, "#fff")
            return f"""
            <tr>
              <td style="background:{color};font-weight:bold">{sev}</td>
              <td>{f['type']}</td>
              <td><a href="{f['source_url']}" target="_blank">{f['repo']}</a></td>
              <td>{f['filename']}</td>
              <td>{f['line_number']}</td>
              <td><code>{f['matched_value']}</code></td>
            </tr>"""

        rows_html = "\n".join(row(f) for f in findings)

        html = f"""<!DOCTYPE html>
<html><head>
  <meta charset="utf-8">
  <title>GitHunt Report - {keyword}</title>
  <style>
    body {{ font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; }}
    h1 {{ color: #00ff88; }}
    .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
    .card {{ padding: 15px 25px; border-radius: 8px; text-align: center; }}
    .high {{ background: #ff4d4d22; border: 1px solid #ff4d4d; }}
    .medium {{ background: #ffa64d22; border: 1px solid #ffa64d; }}
    .low {{ background: #ffff4d22; border: 1px solid #ffff4d; }}
    .card h2 {{ font-size: 2em; margin: 0; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
    th {{ background: #0f3460; padding: 10px; text-align: left; }}
    td {{ padding: 8px 10px; border-bottom: 1px solid #333; }}
    tr:hover {{ background: #ffffff11; }}
    a {{ color: #00aaff; }}
    code {{ background: #333; padding: 2px 6px; border-radius: 4px; }}
  </style>
</head>
<body>
  <h1>🔍 GitHunt Report</h1>
  <p>Keyword: <strong>{keyword}</strong> | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

  <div class="summary">
    <div class="card high"><h2>{len(high)}</h2>HIGH</div>
    <div class="card medium"><h2>{len(medium)}</h2>MEDIUM</div>
    <div class="card low"><h2>{len(low)}</h2>LOW</div>
  </div>

  <table>
    <tr>
      <th>Severity</th><th>Type</th><th>Repository</th>
      <th>File</th><th>Line</th><th>Value (redacted)</th>
    </tr>
    {rows_html}
  </table>
</body></html>"""

        with open(filename, "w") as f:
            f.write(html)
