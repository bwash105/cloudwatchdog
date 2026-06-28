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


def check_iam_admin_policy_users(session):
    findings = []
    iam = session.client("iam")
    try:
        users = iam.list_users().get("Users", [])
        for user in users:
            username = user["UserName"]
            policies = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
            for policy in policies:
                if policy["PolicyArn"].endswith(":policy/AdministratorAccess") or policy["PolicyArn"] == "arn:aws:iam::aws:policy/AdministratorAccess":
                    findings.append({
                        "resource": f"iam::{username}",
                        "check": "iam_admin_policy_on_user",
                        "severity": "HIGH",
                        "detail": f"User {username} has AdministratorAccess policy attached directly.",
                        "remediation": "Remove direct policy. Add user to an admin group or grant access via role assumption.",
                    })
    except Exception:
        pass
    return findings


def check_iam_wildcard_trust(session):
    findings = []
    iam = session.client("iam")
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                trust_doc = role.get("AssumeRolePolicyDocument", {})
                for stmt in trust_doc.get("Statement", []):
                    principal = stmt.get("Principal")
                    if principal == "*":
                        findings.append({
                            "resource": f"iam::role:{role['RoleName']}",
                            "check": "iam_wildcard_trust_policy",
                            "severity": "CRITICAL",
                            "detail": f"Role {role['RoleName']} trust policy uses Principal: '*' — assumable by anyone.",
                            "remediation": "Restrict Principal to specific AWS accounts, services, or ARNs. Add Condition constraints if cross-account access is required.",
                        })
    except Exception:
        pass
    return findings


def check_sg_all_traffic_open(session):
    findings = []
    ec2 = session.client("ec2")
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        for sg in sgs:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "unnamed")
            for perm in sg.get("IpPermissions", []):
                if perm.get("IpProtocol") == "-1":
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") in ("0.0.0.0/0", "::/0"):
                            findings.append({
                                "resource": f"sg:{sg_id} ({sg_name})",
                                "check": "sg_all_traffic_open",
                                "severity": "CRITICAL",
                                "detail": f"Security group {sg_id} allows ALL traffic (protocol -1) from {ip_range['CidrIp']}.",
                                "remediation": "Remove the all-traffic ingress rule. Define specific port/protocol rules for required access.",
                            })
    except Exception:
        pass
    return findings


def check_public_ec2_in_public_subnet(session):
    findings = []
    ec2 = session.client("ec2")
    try:
        # Identify public subnets: subnets associated with a route table
        # that has a route 0.0.0.0/0 → igw-*
        route_tables = ec2.describe_route_tables().get("RouteTables", [])
        public_subnet_ids: set[str] = set()
        for rt in route_tables:
            has_igw_route = any(
                route.get("GatewayId", "").startswith("igw-")
                and route.get("DestinationCidrBlock") == "0.0.0.0/0"
                for route in rt.get("Routes", [])
            )
            if has_igw_route:
                for assoc in rt.get("Associations", []):
                    if "SubnetId" in assoc:
                        public_subnet_ids.add(assoc["SubnetId"])

        reservations = ec2.describe_instances().get("Reservations", [])
        for reservation in reservations:
            for instance in reservation.get("Instances", []):
                if instance.get("State", {}).get("Name") not in ("running", "stopped"):
                    continue
                subnet_id = instance.get("SubnetId", "")
                public_ip = instance.get("PublicIpAddress")
                if subnet_id in public_subnet_ids and public_ip:
                    instance_id = instance["InstanceId"]
                    findings.append({
                        "resource": f"ec2:{instance_id} (public IP: {public_ip})",
                        "check": "public_ec2_in_public_subnet",
                        "severity": "MEDIUM",
                        "detail": f"Instance {instance_id} in public subnet {subnet_id} has a public IP assigned.",
                        "remediation": "Use a NAT gateway for outbound access. Remove public IP assignment. Place internet-facing services behind an ALB.",
                    })
    except Exception:
        pass
    return findings


def check_cloudtrail_log_validation(session):
    findings = []
    ct = session.client("cloudtrail")
    try:
        trails = ct.describe_trails().get("trailList", [])
        for trail in trails:
            if not trail.get("LogFileValidationEnabled", False):
                findings.append({
                    "resource": f"cloudtrail:{trail.get('Name', 'unnamed')}",
                    "check": "cloudtrail_log_validation_disabled",
                    "severity": "HIGH",
                    "detail": f"Trail {trail.get('Name')} has log file validation disabled — logs can be tampered with undetected.",
                    "remediation": "Enable log file validation: aws cloudtrail update-trail --name <name> --enable-log-file-validation",
                })
    except Exception:
        pass
    return findings


def check_guardduty_enabled(session):
    findings = []
    gd = session.client("guardduty")
    try:
        detector_ids = gd.list_detectors().get("DetectorIds", [])
        if not detector_ids:
            findings.append({
                "resource": "guardduty::account",
                "check": "guardduty_not_enabled",
                "severity": "HIGH",
                "detail": "GuardDuty is not enabled. No threat detection layer for API calls, DNS, or network traffic.",
                "remediation": "Enable GuardDuty: aws guardduty create-detector --enable. Enable in all active regions.",
            })
        else:
            for detector_id in detector_ids:
                detector = gd.get_detector(DetectorId=detector_id)
                if detector.get("Status") != "ENABLED":
                    findings.append({
                        "resource": f"guardduty::detector:{detector_id}",
                        "check": "guardduty_not_enabled",
                        "severity": "HIGH",
                        "detail": f"GuardDuty detector {detector_id} exists but is not enabled.",
                        "remediation": f"Enable the detector: aws guardduty update-detector --detector-id {detector_id} --enable",
                    })
    except Exception:
        pass
    return findings


def check_config_enabled(session):
    findings = []
    cfg = session.client("config")
    try:
        recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
        if not recorders:
            findings.append({
                "resource": "config::account",
                "check": "config_not_enabled",
                "severity": "MEDIUM",
                "detail": "AWS Config is not configured. No resource change history for compliance audits or forensics.",
                "remediation": "Enable AWS Config with a delivery channel to S3. aws configservice put-configuration-recorder and put-delivery-channel.",
            })
            return findings

        status_list = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
        for status in status_list:
            if not status.get("recording", False):
                findings.append({
                    "resource": f"config::recorder:{status.get('name', 'default')}",
                    "check": "config_not_enabled",
                    "severity": "MEDIUM",
                    "detail": f"AWS Config recorder {status.get('name')} exists but is not recording.",
                    "remediation": "Start the recorder: aws configservice start-configuration-recorder --configuration-recorder-name default",
                })
    except Exception:
        pass
    return findings


def check_s3_access_logging(session):
    findings = []
    s3 = session.client("s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            try:
                logging_config = s3.get_bucket_logging(Bucket=name)
                if "LoggingEnabled" not in logging_config:
                    findings.append({
                        "resource": f"s3://{name}",
                        "check": "s3_access_logging_disabled",
                        "severity": "MEDIUM",
                        "detail": f"Bucket {name} has no server access logging. Read/write operations are not audited.",
                        "remediation": "Enable server access logging: aws s3api put-bucket-logging. Send logs to a dedicated audit bucket.",
                    })
            except Exception:
                pass
    except Exception:
        pass
    return findings


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
