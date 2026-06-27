"""CloudWatchdog — AWS Cloud Security Posture Monitor."""

import argparse
import os
from datetime import datetime, timezone

import boto3

from checks import run_all_checks, SEVERITY
from compliance import compute_compliance
from llm_remediation import enrich_with_playbooks
from reporter import print_report, write_json_report, write_html_report


def run_scan(
    profile: str | None = None,
    region: str = "us-east-1",
    llm: bool = False,
) -> tuple[list[dict], dict]:
    session = boto3.Session(profile_name=profile, region_name=region)

    print(f"\n🔍 CloudWatchdog — AWS Security Posture Scan")
    print(f"   Region: {region} | Profile: {profile or 'default'}")
    print(f"   Time: {datetime.now(timezone.utc).isoformat()}\n")

    check_results = run_all_checks(session, verbose=True)
    all_findings = [f for _, findings in check_results for f in findings]
    all_findings.sort(key=lambda f: SEVERITY.get(f["severity"], 0), reverse=True)

    compliance_scores = compute_compliance(check_results)

    if llm:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            print("⚠️  --llm flag set but ANTHROPIC_API_KEY not found in environment. Skipping playbooks.")
        else:
            print("\n🤖 Generating LLM remediation playbooks...")
            all_findings = enrich_with_playbooks(all_findings, api_key)

    return all_findings, compliance_scores


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CloudWatchdog AWS security posture scan")
    parser.add_argument("profile", nargs="?", default=None, help="AWS profile name")
    parser.add_argument("region", nargs="?", default="us-east-1", help="AWS region")
    parser.add_argument("--html", nargs="?", const="cloudwatchdog-report.html",
                        default="cloudwatchdog-report.html")
    parser.add_argument("--llm", action="store_true", help="Generate LLM remediation playbooks")
    args = parser.parse_args()

    scan_time = datetime.now(timezone.utc).isoformat()
    findings, compliance_scores = run_scan(profile=args.profile, region=args.region, llm=args.llm)
    print_report(findings, compliance_scores)

    write_json_report(findings, compliance_scores, scan_time, args.region, path="cloudwatchdog-report.json")
    print("📄 JSON report saved: cloudwatchdog-report.json")

    write_html_report(findings, compliance_scores, scan_time, args.region, args.profile, path=args.html)
    print(f"📊 HTML report saved: {args.html}\n")
