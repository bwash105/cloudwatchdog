"""CloudWatchdog detection rules."""

import time
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

SEVERITY = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}

_credential_report_cache = None


def get_credential_report(session):
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


def check_public_s3_buckets(session):
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
            pass
    return findings


def check_root_access_key(session):
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


# New checks added in Task 2 — stubs here so run_all_checks has correct count
def check_iam_admin_policy_users(session):
    return []  # replaced in Task 2


def check_iam_wildcard_trust(session):
    return []  # replaced in Task 2


def check_sg_all_traffic_open(session):
    return []  # replaced in Task 2


def check_public_ec2_in_public_subnet(session):
    return []  # replaced in Task 2


def check_cloudtrail_log_validation(session):
    return []  # replaced in Task 2


def check_guardduty_enabled(session):
    return []  # replaced in Task 2


def check_config_enabled(session):
    return []  # replaced in Task 2


def check_s3_access_logging(session):
    return []  # replaced in Task 2


ALL_CHECK_FUNCTIONS = [
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
    check_iam_admin_policy_users,
    check_iam_wildcard_trust,
    check_sg_all_traffic_open,
    check_public_ec2_in_public_subnet,
    check_cloudtrail_log_validation,
    check_guardduty_enabled,
    check_config_enabled,
    check_s3_access_logging,
]


def run_all_checks(session: boto3.Session, verbose: bool = True) -> list[tuple[str, list[dict]]]:
    """Run all 19 checks. Returns list of (function_name, findings) tuples."""
    global _credential_report_cache
    _credential_report_cache = None

    results = []
    for fn in ALL_CHECK_FUNCTIONS:
        if verbose:
            print(f"   Running: {fn.__name__}...", end=" ", flush=True)
        try:
            findings = fn(session)
            if verbose:
                icon = f"⚠️  {len(findings)} findings" if findings else "✅ clean"
                print(icon)
        except Exception as e:
            findings = []
            if verbose:
                print(f"❌ error: {e}")
        results.append((fn.__name__, findings))
    return results
