"""
core/reporter.py
Generates reports from scan findings in JSON, CSV, or HTML format.
"""

import csv
import html
import json
import logging
import os
from datetime import datetime
from typing import List, Dict

logger = logging.getLogger(__name__)


class Reporter:
    def __init__(self, output_format: str = "json", output_dir: str = "."):
        self.format = output_format
        self.output_dir = output_dir

    def save(self, findings: List[Dict], keyword: str) -> str:
        """Save findings to file and return the output filename."""
        os.makedirs(self.output_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_keyword = keyword.replace("/", "_").replace(".", "_")
        filename = os.path.join(
            self.output_dir,
            f"githunt_{safe_keyword}_{timestamp}.{self.format}"
        )

        if self.format == "json":
            self._save_json(findings, filename, keyword)
        elif self.format == "csv":
            self._save_csv(findings, filename)
        elif self.format == "html":
            self._save_html(findings, filename, keyword)

        logger.info("Report saved to %s", filename)
        return filename

    def _save_json(self, findings: List[Dict], filename: str, keyword: str) -> None:
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
        with open(filename, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)

    def _save_csv(self, findings: List[Dict], filename: str) -> None:
        if not findings:
            with open(filename, "w", encoding="utf-8") as fh:
                fh.write("No findings.\n")
            return

        fields = ["severity", "type", "repo", "filename", "line_number",
                  "matched_value", "source_url", "timestamp", "entropy"]

        with open(filename, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(findings)

    def _save_html(self, findings: List[Dict], filename: str, keyword: str) -> None:
        high   = [f for f in findings if f["severity"] == "HIGH"]
        medium = [f for f in findings if f["severity"] == "MEDIUM"]
        low    = [f for f in findings if f["severity"] == "LOW"]

        def row(f: Dict) -> str:
            sev = f["severity"]
            color = {"HIGH": "#ff4d4d", "MEDIUM": "#ffa64d", "LOW": "#ffff4d"}.get(sev, "#fff")
            # Escape all user-controlled fields to prevent XSS
            esc_sev      = html.escape(sev)
            esc_type     = html.escape(f["type"])
            esc_repo     = html.escape(f["repo"])
            esc_url      = html.escape(f["source_url"])
            esc_filename = html.escape(f["filename"])
            esc_line     = html.escape(str(f["line_number"]))
            esc_value    = html.escape(f["matched_value"])
            entropy_val  = html.escape(str(f.get("entropy", "")))
            return (
                f"<tr>"
                f'<td style="background:{color};font-weight:bold">{esc_sev}</td>'
                f"<td>{esc_type}</td>"
                f'<td><a href="{esc_url}" target="_blank" rel="noopener noreferrer">{esc_repo}</a></td>'
                f"<td>{esc_filename}</td>"
                f"<td>{esc_line}</td>"
                f"<td><code>{esc_value}</code></td>"
                f"<td>{entropy_val}</td>"
                f"</tr>"
            )

        rows_html = "\n".join(row(f) for f in findings)
        esc_keyword = html.escape(keyword)
        generated  = html.escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        page = f"""<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GitHunt Report - {esc_keyword}</title>
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
    td {{ padding: 8px 10px; border-bottom: 1px solid #333; overflow-wrap: break-word; }}
    tr:hover {{ background: #ffffff11; }}
    a {{ color: #00aaff; }}
    code {{ background: #333; padding: 2px 6px; border-radius: 4px; }}
  </style>
</head>
<body>
  <h1>&#128269; GitHunt Report</h1>
  <p>Keyword: <strong>{esc_keyword}</strong> | Generated: {generated}</p>

  <div class="summary">
    <div class="card high"><h2>{len(high)}</h2>HIGH</div>
    <div class="card medium"><h2>{len(medium)}</h2>MEDIUM</div>
    <div class="card low"><h2>{len(low)}</h2>LOW</div>
  </div>

  <table>
    <tr>
      <th>Severity</th><th>Type</th><th>Repository</th>
      <th>File</th><th>Line</th><th>Value</th><th>Entropy</th>
    </tr>
    {rows_html}
  </table>
</body></html>"""

        with open(filename, "w", encoding="utf-8") as fh:
            fh.write(page)
