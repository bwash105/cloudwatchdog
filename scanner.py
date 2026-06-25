"""
CloudWatchdog — AWS Cloud Security Posture Monitor
PM artifact: detection schema + severity classification framework
GitHub: github.com/bwash105/cloudwatchdog
"""

import boto3
import json
from datetime import datetime, timezone

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
    iam = session.client("iam")
    try:
        report = iam.generate_credential_report()
        # Wait for report
        import time
        time.sleep(2)
        result = iam.get_credential_report()
        content = result["Content"].decode("utf-8").splitlines()
        headers = content[0].split(",")
        for row in content[1:]:
            fields = dict(zip(headers, row.split(",")))
            if fields.get("user") == "<root_account>":
                if fields.get("access_key_1_active") == "true" or fields.get("access_key_2_active") == "true":
                    findings.append({
                        "resource": "iam::root",
                        "check": "root_access_key_active",
                        "severity": "CRITICAL",
                        "detail": "Root account has active API access keys.",
                        "remediation": "Delete root access keys immediately. Use IAM roles for programmatic access.",
                    })
    except Exception as e:
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


# ─── Report Generation ────────────────────────────────────────────────────────

def run_scan(profile=None, region="us-east-1"):
    """Run all detection rules and return prioritized findings."""
    session = boto3.Session(profile_name=profile, region_name=region)

    print(f"\n🔍 CloudWatchdog — AWS Security Posture Scan")
    print(f"   Region: {region} | Profile: {profile or 'default'}")
    print(f"   Time: {datetime.now(timezone.utc).isoformat()}\n")

    all_checks = [
        check_public_s3_buckets,
        check_root_access_key,
        check_open_ssh_rdp,
        check_mfa_root,
        check_unencrypted_ebs,
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


if __name__ == "__main__":
    import sys
    profile = sys.argv[1] if len(sys.argv) > 1 else None
    region = sys.argv[2] if len(sys.argv) > 2 else "us-east-1"
    findings = run_scan(profile=profile, region=region)
    print_report(findings)

    # JSON output for downstream integration
    with open("cloudwatchdog-report.json", "w") as f:
        json.dump({
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "region": region,
            "findings": findings,
        }, f, indent=2)
    print(f"📄 JSON report saved: cloudwatchdog-report.json\n")
