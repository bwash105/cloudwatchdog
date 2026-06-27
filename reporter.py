"""CloudWatchdog output rendering — terminal, JSON, HTML."""

import html
import json

SEVERITY_COLORS = {
    "CRITICAL": ("#dc2626", "#fef2f2"),
    "HIGH": ("#ea580c", "#fff7ed"),
    "MEDIUM": ("#ca8a04", "#fefce8"),
    "LOW": ("#2563eb", "#eff6ff"),
}

SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}


def print_report(findings: list[dict], compliance_scores: dict) -> None:
    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\n" + "═" * 60)
    print("CLOUDWATCHDOG — SECURITY POSTURE REPORT")
    print("═" * 60)

    if not findings:
        print("\n✅ No findings. Account passes all configured checks.\n")
    else:
        print(f"\nFindings: {len(findings)} total")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = severity_counts.get(sev, 0)
            if count:
                print(f"  {SEVERITY_ICONS[sev]} {sev}: {count}")
        print()
        for i, finding in enumerate(findings, 1):
            sev = finding["severity"]
            icon = SEVERITY_ICONS.get(sev, "⚪")
            print(f"{i}. {icon} [{sev}] {finding['check']}")
            print(f"   Resource:     {finding['resource']}")
            print(f"   Detail:       {finding['detail']}")
            print(f"   Remediation:  {finding['remediation']}")
            if "playbook" in finding:
                pb = finding["playbook"]
                print(f"   Playbook:")
                print(f"     Immediate:  {'; '.join(pb.get('immediate_steps', []))}")
                print(f"     Verify:     {pb.get('verification', '')}")
                print(f"     Long-term:  {'; '.join(pb.get('long_term_controls', []))}")
                print(f"     Blast:      {pb.get('blast_radius', '')}")
            print()

    _print_compliance(compliance_scores)


def _print_compliance(compliance_scores: dict) -> None:
    cis = compliance_scores.get("cis_aws_v2", {})
    nist = compliance_scores.get("nist_csf_coverage", {})

    passing = cis.get("passing", 0)
    total = cis.get("total", 0)
    pct = cis.get("score_pct", 0)
    bar_filled = int(pct / 100 * 24)
    bar = "█" * bar_filled + "░" * (24 - bar_filled)

    print("─" * 60)
    print("COMPLIANCE SCORE")
    print("─" * 60)
    print(f"CIS AWS Foundations Benchmark v2")
    print(f"  {passing} / {total} controls passing  ({pct}%)")
    print(f"  {bar} {pct}%")
    print()
    print("NIST CSF Coverage (informational)")
    for fn in ["identify", "protect", "detect"]:
        data = nist.get(fn, {})
        if isinstance(data, dict):
            print(f"  {fn.capitalize():<12} {data.get('passing', 0)}/{data.get('total', 0)} passing")
    print(f"  {'Respond':<12} covered by LLM playbooks")
    print(f"  {'Recover':<12} out of scope")
    print("─" * 60 + "\n")


def write_json_report(
    findings: list[dict],
    compliance_scores: dict,
    scan_time: str,
    region: str,
    path: str = "cloudwatchdog-report.json",
) -> None:
    report = {
        "scan_time": scan_time,
        "region": region,
        "compliance_scores": compliance_scores,
        "findings": findings,
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2)


def write_html_report(
    findings: list[dict],
    compliance_scores: dict,
    scan_time: str,
    region: str,
    profile: str | None,
    path: str = "cloudwatchdog-report.html",
) -> None:
    severity_counts = {sev: 0 for sev in SEVERITY_COLORS}
    for finding in findings:
        sev = finding.get("severity", "LOW")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    summary_cards = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        fg, bg = SEVERITY_COLORS[sev]
        count = severity_counts.get(sev, 0)
        summary_cards.append(
            f'<div class="card" style="border-color:{fg};background:{bg}">'
            f'<div class="count" style="color:{fg}">{count}</div>'
            f'<div class="label">{html.escape(sev)}</div></div>'
        )

    cis = compliance_scores.get("cis_aws_v2", {})
    nist = compliance_scores.get("nist_csf_coverage", {})
    cis_pct = cis.get("score_pct", 0)
    cis_passing = cis.get("passing", 0)
    cis_total = cis.get("total", 0)

    nist_rows = ""
    for fn in ["identify", "protect", "detect"]:
        data = nist.get(fn, {})
        if isinstance(data, dict):
            p = data.get("passing", 0)
            t = data.get("total", 0)
            fn_pct = round(p / t * 100) if t else 0
            nist_rows += (
                f"<div class='nist-row'>"
                f"<span class='nist-label'>{html.escape(fn.capitalize())}</span>"
                f"<div class='nist-bar-wrap'>"
                f"<div class='nist-bar' style='width:{fn_pct}%'></div>"
                f"</div>"
                f"<span class='nist-count'>{p}/{t}</span>"
                f"</div>"
            )

    rows = []
    for i, finding in enumerate(findings, 1):
        sev = finding.get("severity", "LOW")
        fg, bg = SEVERITY_COLORS.get(sev, ("#64748b", "#f8fafc"))
        playbook_html = ""
        if "playbook" in finding:
            pb = finding["playbook"]
            steps = "".join(f"<li>{html.escape(s)}</li>" for s in pb.get("immediate_steps", []))
            controls = "".join(f"<li>{html.escape(s)}</li>" for s in pb.get("long_term_controls", []))
            playbook_html = (
                f"<tr class='playbook-row'><td colspan='6'>"
                f"<details><summary>🤖 LLM Remediation Playbook</summary>"
                f"<div class='playbook'>"
                f"<strong>Immediate steps:</strong><ol>{steps}</ol>"
                f"<strong>Verify:</strong><p>{html.escape(pb.get('verification', ''))}</p>"
                f"<strong>Long-term controls:</strong><ul>{controls}</ul>"
                f"<strong>Blast radius:</strong><p>{html.escape(pb.get('blast_radius', ''))}</p>"
                f"</div></details></td></tr>"
            )
        rows.append(
            "<tr>"
            f"<td>{i}</td>"
            f'<td><span class="badge" style="color:{fg};background:{bg}">{html.escape(sev)}</span></td>'
            f"<td><code>{html.escape(finding.get('check', ''))}</code></td>"
            f"<td>{html.escape(finding.get('resource', ''))}</td>"
            f"<td>{html.escape(finding.get('detail', ''))}</td>"
            f"<td>{html.escape(finding.get('remediation', ''))}</td>"
            "</tr>"
            + playbook_html
        )

    findings_body = "\n".join(rows) if rows else (
        '<tr><td colspan="6" class="clean">No findings. Account passes all configured checks.</td></tr>'
    )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CloudWatchdog Report</title>
  <style>
    :root {{ color-scheme: light; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.5; }}
    body {{ margin: 0; background: #f8fafc; color: #0f172a; }}
    .wrap {{ max-width: 1200px; margin: 0 auto; padding: 2rem 1.25rem 3rem; }}
    h1 {{ margin: 0 0 0.25rem; font-size: 1.75rem; }}
    h2 {{ font-size: 1.1rem; margin: 1.5rem 0 0.75rem; color: #334155; }}
    .meta {{ color: #64748b; margin-bottom: 1.5rem; font-size: 0.95rem; }}
    .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.75rem; margin-bottom: 1.5rem; }}
    .card {{ border: 1px solid; border-radius: 0.75rem; padding: 1rem; text-align: center; }}
    .count {{ font-size: 2rem; font-weight: 700; line-height: 1.1; }}
    .label {{ font-size: 0.85rem; font-weight: 600; letter-spacing: 0.04em; }}
    .compliance-panel {{ background: white; border-radius: 0.75rem; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(15,23,42,.08); }}
    .cis-score {{ font-size: 1.5rem; font-weight: 700; color: #0f172a; }}
    .cis-bar-wrap {{ background: #e2e8f0; border-radius: 999px; height: 12px; margin: 0.5rem 0; }}
    .cis-bar {{ background: #16a34a; border-radius: 999px; height: 12px; width: {cis_pct}%; }}
    .nist-row {{ display: flex; align-items: center; gap: 0.75rem; margin: 0.4rem 0; }}
    .nist-label {{ width: 80px; font-size: 0.85rem; font-weight: 600; color: #475569; }}
    .nist-bar-wrap {{ flex: 1; background: #e2e8f0; border-radius: 999px; height: 8px; }}
    .nist-bar {{ background: #3b82f6; border-radius: 999px; height: 8px; }}
    .nist-count {{ font-size: 0.8rem; color: #64748b; width: 36px; text-align: right; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 0.75rem; overflow: hidden; box-shadow: 0 1px 3px rgba(15,23,42,.08); }}
    th, td {{ padding: 0.85rem 0.75rem; border-bottom: 1px solid #e2e8f0; vertical-align: top; text-align: left; }}
    th {{ background: #0f172a; color: white; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    tr:last-child td {{ border-bottom: none; }}
    .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.75rem; font-weight: 700; }}
    code {{ font-size: 0.85rem; background: #f1f5f9; padding: 0.1rem 0.35rem; border-radius: 0.25rem; }}
    .clean {{ text-align: center; color: #16a34a; font-weight: 600; padding: 2rem; }}
    .playbook-row td {{ background: #f8fafc; padding: 0.5rem 1rem; }}
    .playbook {{ font-size: 0.875rem; padding: 0.5rem; }}
    .playbook ol, .playbook ul {{ margin: 0.25rem 0 0.75rem 1.25rem; padding: 0; }}
    .playbook p {{ margin: 0.25rem 0 0.75rem; }}
    details summary {{ cursor: pointer; color: #2563eb; font-size: 0.875rem; font-weight: 600; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>CloudWatchdog — Security Posture Report</h1>
    <div class="meta">
      Scan time: {html.escape(scan_time)}<br>
      Region: {html.escape(region)} | Profile: {html.escape(profile or "default")}<br>
      Findings: {len(findings)}
    </div>
    <div class="summary">{"".join(summary_cards)}</div>
    <div class="compliance-panel">
      <h2>Compliance Score</h2>
      <div class="cis-score">{cis_pct}% <span style="font-size:1rem;font-weight:400;color:#64748b;">CIS AWS Foundations Benchmark v2 ({cis_passing}/{cis_total} controls)</span></div>
      <div class="cis-bar-wrap"><div class="cis-bar"></div></div>
      <div style="margin-top:1rem">{nist_rows}</div>
    </div>
    <table>
      <thead>
        <tr><th>#</th><th>Severity</th><th>Check</th><th>Resource</th><th>Detail</th><th>Remediation</th></tr>
      </thead>
      <tbody>{findings_body}</tbody>
    </table>
  </div>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(doc)
