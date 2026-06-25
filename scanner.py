"""
CloudWatchdog — AWS Cloud Security Posture Monitor
PM artifact: detection schema + severity classification framework
GitHub: github.com/bwash105/cloudwatchdog
"""

import argparse
import boto3
import html
import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

# ─── Severity Framework ───────────────────────────────────────────────────────
# Designed as a PM artifact: what warrants each level and why.
#
# CRITICAL — exploitable now, no attacker action needed, full account at risk
# HIGH     — attacker needs one more step; exploits common, well-documented
# MEDIUM   — increases attack surface, no direct exploit path today
# LOW      — hardening gap, minimal immediate risk

SEVERITY = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


# ─── Helpers ──────────────────────────────────────────────────────────────────

_credential_report_cache = None


def get_credential_report(session):
    """Fetch IAM credential report rows as list of dicts (cached per scan)."""
    global _credential_report_cache
    if _credential_report_cache is not None:
        return _credential_report_cache

    iam = session.client("iam")
    iam.generate_credential_report()
    time.sleep(2)
    result = iam.get_credential_report()
    content = result["Content"].decode("utf-8").splitlines()
    headers = content[0].split(",")
    _credential_report_cache = [dict(zip(headers, row.split(","))) for row in content[1:]]
    return _credential_report_cache


def parse_aws_date(value):
    if not value or value in ("N/A", "not_supported", "no_information"):
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S+00:00"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# ─── Detection Rules ──────────────────────────────────────────────────────────

def check_public_s3_buckets(session):
    """
    PUBLIC S3 BUCKETS — CRITICAL
    ACL or bucket policy grants read/write to AllUsers or AuthenticatedUsers.
    Most common cause of cloud data breaches (Capital One, Twitch, etc.).
    """
    findings = []
    s3 = session.client("s3")
    buckets = s3.list_buckets().get("Buckets", [])

    for bucket in buckets:
        name = bucket["Name"]
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    findings.append({
                        "resource": f"s3://{name}",
                        "check": "public_s3_bucket",
                        "severity": "CRITICAL",
                        "detail": f"Bucket ACL grants access to {uri}",
                        "remediation": "Remove public ACL grants. Enable S3 Block Public Access at account level.",
                    })
        except Exception:
            pass  # Access denied to check = not our bucket or expected

    return findings


def check_root_access_key(session):
    """
    ROOT ACCESS KEY ACTIVE — CRITICAL
    AWS root account has API keys. Root = full account access, no restrictions.
    If key is leaked, attacker owns the account entirely.
    """
    findings = []
    try:
        for fields in get_credential_report(session):
            if fields.get("user") == "<root_account>":
                if fields.get("access_key_1_active") == "true" or fields.get("access_key_2_active") == "true":
                    findings.append({
                        "resource": "iam::root",
                        "check": "root_access_key_active",
                        "severity": "CRITICAL",
                        "detail": "Root account has active API access keys.",
                        "remediation": "Delete root access keys immediately. Use IAM roles for programmatic access.",
                    })
    except Exception:
        pass

    return findings


def check_open_ssh_rdp(session):
    """
    SECURITY GROUPS — OPEN SSH/RDP TO WORLD — HIGH
    Inbound rule allows 0.0.0.0/0 on port 22 (SSH) or 3389 (RDP).
    Enables brute force and credential stuffing attacks directly against instances.
    """
    findings = []
    ec2 = session.client("ec2")
    sgs = ec2.describe_security_groups().get("SecurityGroups", [])

    for sg in sgs:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", "unnamed")
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort", 0)
            to_port = perm.get("ToPort", 65535)
            for ip_range in perm.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "")
                if cidr in ("0.0.0.0/0", "::/0"):
                    for port, label in [(22, "SSH"), (3389, "RDP")]:
                        if from_port <= port <= to_port:
                            findings.append({
                                "resource": f"sg:{sg_id} ({sg_name})",
                                "check": "open_ssh_rdp_to_world",
                                "severity": "HIGH",
                                "detail": f"Port {port} ({label}) open to {cidr}",
                                "remediation": f"Restrict port {port} to known IPs or VPN CIDR range.",
                            })

    return findings


def check_mfa_root(session):
    """
    ROOT MFA NOT ENABLED — HIGH
    Root account login without MFA — credential phishing = game over.
    """
    findings = []
    iam = session.client("iam")
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 0:
            findings.append({
                "resource": "iam::root",
                "check": "root_mfa_not_enabled",
                "severity": "HIGH",
                "detail": "Root account does not have MFA enabled.",
                "remediation": "Enable MFA on root account via AWS Console → Security Credentials.",
            })
    except Exception:
        pass

    return findings


def check_unencrypted_ebs(session):
    """
    UNENCRYPTED EBS VOLUMES — MEDIUM
    Data at rest on unencrypted volumes. Lower severity: requires physical/hypervisor access.
    Important for compliance (SOC 2, PCI, HIPAA).
    """
    findings = []
    ec2 = session.client("ec2")
    volumes = ec2.describe_volumes().get("Volumes", [])

    for vol in volumes:
        if not vol.get("Encrypted", False):
            findings.append({
                "resource": f"ebs:{vol['VolumeId']}",
                "check": "unencrypted_ebs_volume",
                "severity": "MEDIUM",
                "detail": f"Volume {vol['VolumeId']} ({vol.get('Size', '?')} GiB) is unencrypted.",
                "remediation": "Create encrypted snapshot and restore as encrypted volume. Enable EBS encryption by default in account settings.",
            })

    return findings


def check_cloudtrail_disabled(session):
    """
    CLOUDTRAIL NOT ENABLED — MEDIUM
    No audit log = blind to API calls, unauthorized access, and incidents.
    Required for forensics, incident response, and most compliance frameworks.
    """
    findings = []
    ct = session.client("cloudtrail")
    try:
        trails = ct.describe_trails().get("trailList", [])
        if not trails:
            findings.append({
                "resource": "cloudtrail::account",
                "check": "cloudtrail_not_enabled",
                "severity": "MEDIUM",
                "detail": "No CloudTrail trails configured in this account.",
                "remediation": "Enable CloudTrail with multi-region logging and log file validation. Store logs in S3 with access logging.",
            })
    except Exception:
        pass

    return findings


def check_iam_password_policy(session):
    """
    IAM PASSWORD POLICY — MEDIUM
    CIS 1.8–1.9: minimum length 14, reuse prevention 24, complexity requirements.
    CIS 1.10: IAM users with console password but no MFA.
    """
    findings = []
    iam = session.client("iam")

    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            findings.append({
                "resource": "iam::account",
                "check": "iam_password_policy_missing",
                "severity": "MEDIUM",
                "detail": "No IAM account password policy configured.",
                "remediation": "Set a password policy: min length 14, reuse prevention 24, and character complexity requirements.",
            })
        return findings

    gaps = []
    if policy.get("MinimumPasswordLength", 0) < 14:
        gaps.append("minimum length < 14")
    if policy.get("PasswordReusePrevention", 0) < 24:
        gaps.append("password reuse prevention < 24")
    if not policy.get("RequireSymbols"):
        gaps.append("symbols not required")
    if not policy.get("RequireNumbers"):
        gaps.append("numbers not required")
    if not policy.get("RequireUppercaseCharacters"):
        gaps.append("uppercase not required")
    if not policy.get("RequireLowercaseCharacters"):
        gaps.append("lowercase not required")

    if gaps:
        findings.append({
            "resource": "iam::account",
            "check": "iam_password_policy_weak",
            "severity": "MEDIUM",
            "detail": f"Password policy gaps: {', '.join(gaps)}.",
            "remediation": "Update IAM password policy to meet CIS 1.8–1.9 (length 14+, reuse 24, full complexity).",
        })

    try:
        for fields in get_credential_report(session):
            user = fields.get("user", "")
            if user == "<root_account>":
                continue
            if fields.get("password_enabled") == "true" and fields.get("mfa_active") != "true":
                findings.append({
                    "resource": f"iam::{user}",
                    "check": "iam_user_mfa_not_enabled",
                    "severity": "HIGH",
                    "detail": f"IAM user {user} has console password but no MFA.",
                    "remediation": "Enable MFA for this IAM user. Enforce MFA via IAM policy or AWS Organizations SCP.",
                })
    except Exception:
        pass

    return findings


def check_public_rds(session):
    """
    PUBLIC RDS INSTANCES — CRITICAL
    Database endpoint reachable from the internet. Direct path to data exfiltration.
    """
    findings = []
    rds = session.client("rds")

    for db in rds.describe_db_instances().get("DBInstances", []):
        if db.get("PubliclyAccessible"):
            findings.append({
                "resource": f"rds:{db['DBInstanceIdentifier']}",
                "check": "public_rds_instance",
                "severity": "CRITICAL",
                "detail": f"RDS instance {db['DBInstanceIdentifier']} is publicly accessible.",
                "remediation": "Set PubliclyAccessible to false. Place RDS in private subnets with access via VPN or bastion.",
            })

    return findings


def check_unused_access_keys(session):
    """
    UNUSED IAM ACCESS KEYS — HIGH
    Active keys unused for 90+ days increase credential theft risk with no operational benefit.
    """
    findings = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)

    try:
        for fields in get_credential_report(session):
            user = fields.get("user", "")
            if user == "<root_account>":
                continue

            for key_num in (1, 2):
                if fields.get(f"access_key_{key_num}_active") != "true":
                    continue

                last_used = parse_aws_date(fields.get(f"access_key_{key_num}_last_used_date"))
                last_rotated = parse_aws_date(fields.get(f"access_key_{key_num}_last_rotated"))

                stale = False
                if last_used is None:
                    if last_rotated and last_rotated < cutoff:
                        stale = True
                elif last_used < cutoff:
                    stale = True

                if stale:
                    findings.append({
                        "resource": f"iam::{user}",
                        "check": "unused_iam_access_key",
                        "severity": "HIGH",
                        "detail": f"Access key {key_num} for {user} unused for 90+ days.",
                        "remediation": "Deactivate or delete unused access keys. Rotate active keys on a 90-day schedule.",
                    })
    except Exception:
        pass

    return findings


def check_vpc_flow_logs(session):
    """
    VPC FLOW LOGS NOT ENABLED — MEDIUM
    No network visibility for forensics, anomaly detection, or compliance (CIS 3.9).
    """
    findings = []
    ec2 = session.client("ec2")
    vpcs = ec2.describe_vpcs().get("Vpcs", [])
    flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])

    vpcs_with_logs = {
        fl["ResourceId"]
        for fl in flow_logs
        if fl.get("FlowLogStatus") == "ACTIVE" and fl.get("ResourceType") == "VPC"
    }

    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        if vpc_id not in vpcs_with_logs:
            name = next(
                (tag["Value"] for tag in vpc.get("Tags", []) if tag.get("Key") == "Name"),
                "unnamed",
            )
            findings.append({
                "resource": f"vpc:{vpc_id} ({name})",
                "check": "vpc_flow_logs_disabled",
                "severity": "MEDIUM",
                "detail": f"VPC {vpc_id} has no active flow logs.",
                "remediation": "Enable VPC Flow Logs to CloudWatch Logs or S3 for all VPCs.",
            })

    return findings


def check_s3_encryption(session):
    """
    S3 SERVER-SIDE ENCRYPTION NOT ENABLED — MEDIUM
    Buckets without default encryption leave data at rest unprotected (CIS 2.1.1).
    """
    findings = []
    s3 = session.client("s3")

    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append({
                    "resource": f"s3://{name}",
                    "check": "s3_encryption_not_enabled",
                    "severity": "MEDIUM",
                    "detail": f"Bucket {name} has no default server-side encryption.",
                    "remediation": "Enable default SSE-S3 or SSE-KMS encryption on the bucket.",
                })

    return findings


# ─── Report Generation ────────────────────────────────────────────────────────

def run_scan(profile=None, region="us-east-1"):
    """Run all detection rules and return prioritized findings."""
    global _credential_report_cache
    _credential_report_cache = None

    session = boto3.Session(profile_name=profile, region_name=region)

    print(f"\n🔍 CloudWatchdog — AWS Security Posture Scan")
    print(f"   Region: {region} | Profile: {profile or 'default'}")
    print(f"   Time: {datetime.now(timezone.utc).isoformat()}\n")

    all_checks = [
        check_public_s3_buckets,
        check_s3_encryption,
        check_root_access_key,
        check_unused_access_keys,
        check_iam_password_policy,
        check_open_ssh_rdp,
        check_mfa_root,
        check_public_rds,
        check_unencrypted_ebs,
        check_vpc_flow_logs,
        check_cloudtrail_disabled,
    ]

    findings = []
    for check in all_checks:
        print(f"   Running: {check.__name__}...", end=" ", flush=True)
        try:
            result = check(session)
            findings.extend(result)
            print(f"{'⚠️  ' + str(len(result)) + ' findings' if result else '✅ clean'}")
        except Exception as e:
            print(f"❌ error: {e}")

    # Sort by severity (CRITICAL first)
    findings.sort(key=lambda f: SEVERITY.get(f["severity"], 0), reverse=True)

    return findings


def print_report(findings):
    severity_counts = {}
    for f in findings:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\n" + "═" * 60)
    print("CLOUDWATCHDOG — SECURITY POSTURE REPORT")
    print("═" * 60)

    if not findings:
        print("\n✅ No findings. Account passes all configured checks.\n")
        return

    print(f"\nFindings: {len(findings)} total")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(sev, 0)
        if count:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}[sev]
            print(f"  {icon} {sev}: {count}")

    print()
    for i, finding in enumerate(findings, 1):
        sev = finding["severity"]
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
        print(f"{i}. {icon} [{sev}] {finding['check']}")
        print(f"   Resource:     {finding['resource']}")
        print(f"   Detail:       {finding['detail']}")
        print(f"   Remediation:  {finding['remediation']}")
        print()


SEVERITY_COLORS = {
    "CRITICAL": ("#dc2626", "#fef2f2"),
    "HIGH": ("#ea580c", "#fff7ed"),
    "MEDIUM": ("#ca8a04", "#fefce8"),
    "LOW": ("#2563eb", "#eff6ff"),
}


def write_html_report(findings, scan_time, region, profile, path="cloudwatchdog-report.html"):
    """Write a self-contained HTML dashboard from scan results."""
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

    rows = []
    for i, finding in enumerate(findings, 1):
        sev = finding.get("severity", "LOW")
        fg, bg = SEVERITY_COLORS.get(sev, ("#64748b", "#f8fafc"))
        rows.append(
            "<tr>"
            f"<td>{i}</td>"
            f'<td><span class="badge" style="color:{fg};background:{bg}">'
            f"{html.escape(sev)}</span></td>"
            f"<td><code>{html.escape(finding.get('check', ''))}</code></td>"
            f"<td>{html.escape(finding.get('resource', ''))}</td>"
            f"<td>{html.escape(finding.get('detail', ''))}</td>"
            f"<td>{html.escape(finding.get('remediation', ''))}</td>"
            "</tr>"
        )

    if rows:
        findings_body = "\n".join(rows)
    else:
        findings_body = (
            '<tr><td colspan="6" class="clean">'
            "No findings. Account passes all configured checks."
            "</td></tr>"
        )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CloudWatchdog Report</title>
  <style>
    :root {{
      color-scheme: light;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }}
    body {{
      margin: 0;
      background: #f8fafc;
      color: #0f172a;
    }}
    .wrap {{
      max-width: 1200px;
      margin: 0 auto;
      padding: 2rem 1.25rem 3rem;
    }}
    h1 {{
      margin: 0 0 0.25rem;
      font-size: 1.75rem;
    }}
    .meta {{
      color: #64748b;
      margin-bottom: 1.5rem;
      font-size: 0.95rem;
    }}
    .summary {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 0.75rem;
      margin-bottom: 1.5rem;
    }}
    .card {{
      border: 1px solid;
      border-radius: 0.75rem;
      padding: 1rem;
      text-align: center;
    }}
    .count {{
      font-size: 2rem;
      font-weight: 700;
      line-height: 1.1;
    }}
    .label {{
      font-size: 0.85rem;
      font-weight: 600;
      letter-spacing: 0.04em;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: white;
      border-radius: 0.75rem;
      overflow: hidden;
      box-shadow: 0 1px 3px rgba(15, 23, 42, 0.08);
    }}
    th, td {{
      padding: 0.85rem 0.75rem;
      border-bottom: 1px solid #e2e8f0;
      vertical-align: top;
      text-align: left;
    }}
    th {{
      background: #0f172a;
      color: white;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    tr:last-child td {{
      border-bottom: none;
    }}
    .badge {{
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 700;
    }}
    code {{
      font-size: 0.85rem;
      background: #f1f5f9;
      padding: 0.1rem 0.35rem;
      border-radius: 0.25rem;
    }}
    .clean {{
      text-align: center;
      color: #16a34a;
      font-weight: 600;
      padding: 2rem;
    }}
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
    <div class="summary">
      {"".join(summary_cards)}
    </div>
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Severity</th>
          <th>Check</th>
          <th>Resource</th>
          <th>Detail</th>
          <th>Remediation</th>
        </tr>
      </thead>
      <tbody>
        {findings_body}
      </tbody>
    </table>
  </div>
</body>
</html>
"""

    with open(path, "w") as f:
        f.write(doc)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CloudWatchdog AWS security posture scan")
    parser.add_argument("profile", nargs="?", default=None, help="AWS profile name")
    parser.add_argument("region", nargs="?", default="us-east-1", help="AWS region")
    parser.add_argument(
        "--html",
        nargs="?",
        const="cloudwatchdog-report.html",
        default="cloudwatchdog-report.html",
        help="Write HTML dashboard (default: cloudwatchdog-report.html)",
    )
    args = parser.parse_args()

    scan_time = datetime.now(timezone.utc).isoformat()
    findings = run_scan(profile=args.profile, region=args.region)
    print_report(findings)

    report = {
        "scan_time": scan_time,
        "region": args.region,
        "findings": findings,
    }
    with open("cloudwatchdog-report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("📄 JSON report saved: cloudwatchdog-report.json")

    write_html_report(findings, scan_time, args.region, args.profile, path=args.html)
    print(f"📊 HTML report saved: {args.html}\n")
