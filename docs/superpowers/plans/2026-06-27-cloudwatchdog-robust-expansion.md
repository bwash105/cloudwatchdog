# CloudWatchdog Robustness Expansion — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand CloudWatchdog from 11 to 19 checks across all four Security+ domains, add LLM-powered remediation playbooks via Claude Haiku, add CIS/NIST compliance scoring, and refactor into clean focused modules.

**Architecture:** Monolithic `scanner.py` splits into `checks.py` (detection), `compliance.py` (scoring), `llm_remediation.py` (playbooks), `reporter.py` (output rendering). `scanner.py` becomes CLI orchestration only. Data flows: `checks.py` → `compliance.py` + optional `llm_remediation.py` → `reporter.py`.

**Tech Stack:** Python 3.10+, boto3, anthropic SDK (`anthropic`), pytest, moto[all]

## Global Constraints

- Python 3.10+ — no walrus operators or match-case required; f-strings and type hints expected
- All AWS API calls go through `boto3.Session` passed as argument — never create sessions inside check functions
- Finding schema (all fields required): `{"resource": str, "check": str, "severity": str, "detail": str, "remediation": str}`
- Severity values: exactly `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"` — no other values
- LLM is opt-in only: `--llm` flag + `ANTHROPIC_API_KEY` env var — no calls without both
- LLM model: `claude-haiku-4-5-20251001` — do not substitute another model
- All tests use `moto[all]` `@mock_aws` decorator — never hit real AWS
- `run_all_checks` return type: `list[tuple[str, list[dict]]]` — list of `(function_name, findings)` tuples

---

## File Structure

```
cloudwatchdog/
├── scanner.py              # MODIFY: slim to CLI + run_scan() orchestration only
├── checks.py               # CREATE: all 19 detection rules + run_all_checks()
├── compliance.py           # CREATE: CIS scoring + NIST categorization
├── llm_remediation.py      # CREATE: Claude API playbook engine
├── reporter.py             # CREATE: terminal + JSON + HTML output
├── requirements.txt        # CREATE: pinned dependencies
├── tests/
│   ├── __init__.py         # CREATE: empty
│   ├── test_checks.py      # CREATE: moto-backed tests for all 19 checks
│   ├── test_compliance.py  # CREATE: pure-Python tests for scoring
│   └── test_llm.py         # CREATE: mocked-API tests for playbook engine
├── DESIGN.md               # MODIFY: add new checks rationale + LLM + compliance sections
├── README.md               # MODIFY: 19-check table, --llm usage, compliance sample output
└── docs/
    ├── SECURITY_DOMAINS.md # CREATE: Security+ objective + CIS + breach example per check
    └── PRODUCT_DECISIONS.md # CREATE: PM decision log for all major choices
```

---

## Task 1: Project Setup + Module Split

**Files:**
- Create: `requirements.txt`
- Create: `checks.py`
- Create: `reporter.py`
- Modify: `scanner.py` (slim to orchestration)
- Create: `tests/__init__.py`
- Create: `tests/test_checks.py` (smoke test only — full tests in Task 2)

**Interfaces:**
- Produces:
  - `checks.run_all_checks(session: boto3.Session, verbose: bool = True) -> list[tuple[str, list[dict]]]`
  - `checks.SEVERITY: dict[str, int]`
  - `reporter.print_report(findings: list[dict], compliance_scores: dict) -> None`
  - `reporter.write_json_report(findings: list[dict], compliance_scores: dict, scan_time: str, region: str, path: str) -> None`
  - `reporter.write_html_report(findings: list[dict], compliance_scores: dict, scan_time: str, region: str, profile: str | None, path: str) -> None`
  - `scanner.run_scan(profile: str | None, region: str, llm: bool) -> tuple[list[dict], dict]`

- [ ] **Step 1: Create requirements.txt**

```
boto3>=1.34
anthropic>=0.28
pytest>=8.0
moto[all]>=5.0
```

- [ ] **Step 2: Install dependencies**

```bash
pip install -r requirements.txt
```

Expected: no errors.

- [ ] **Step 3: Write failing smoke test**

Create `tests/__init__.py` (empty file), then create `tests/test_checks.py`:

```python
import boto3
from moto import mock_aws
from checks import run_all_checks, SEVERITY


@mock_aws
def test_run_all_checks_returns_correct_structure():
    session = boto3.Session(region_name="us-east-1")
    results = run_all_checks(session, verbose=False)
    assert isinstance(results, list)
    assert len(results) == 19
    for name, findings in results:
        assert isinstance(name, str)
        assert name.startswith("check_")
        assert isinstance(findings, list)


def test_severity_values():
    assert SEVERITY["CRITICAL"] == 4
    assert SEVERITY["HIGH"] == 3
    assert SEVERITY["MEDIUM"] == 2
    assert SEVERITY["LOW"] == 1
```

- [ ] **Step 4: Run test to confirm it fails**

```bash
pytest tests/test_checks.py -v
```

Expected: `ImportError: No module named 'checks'`

- [ ] **Step 5: Create checks.py**

```python
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
```

- [ ] **Step 6: Create reporter.py**

```python
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
```

- [ ] **Step 7: Slim scanner.py to orchestration only**

Replace the entire contents of `scanner.py` with:

```python
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
```

- [ ] **Step 8: Create stub llm_remediation.py and compliance.py so imports resolve**

Create `llm_remediation.py`:

```python
"""LLM remediation playbook engine — implemented in Task 4."""


def enrich_with_playbooks(findings: list[dict], api_key: str) -> list[dict]:
    return findings
```

Create `compliance.py`:

```python
"""CIS/NIST compliance scoring — implemented in Task 3."""


def compute_compliance(check_results: list[tuple[str, list[dict]]]) -> dict:
    return {
        "cis_aws_v2": {"passing": 0, "total": len(check_results), "score_pct": 0},
        "nist_csf_coverage": {},
    }
```

- [ ] **Step 9: Run smoke test**

```bash
pytest tests/test_checks.py -v
```

Expected output:
```
PASSED tests/test_checks.py::test_run_all_checks_returns_correct_structure
PASSED tests/test_checks.py::test_severity_values
2 passed
```

- [ ] **Step 10: Commit**

```bash
git add checks.py reporter.py compliance.py llm_remediation.py scanner.py requirements.txt tests/
git commit -m "refactor: split scanner.py into focused modules, add test harness"
```

---

## Task 2: 8 New Detection Checks

**Files:**
- Modify: `checks.py` (replace 8 stub functions with real implementations)
- Modify: `tests/test_checks.py` (add tests for each new check)

**Interfaces:**
- Consumes: `checks.run_all_checks` from Task 1
- Produces: 8 working check functions returning findings with correct schema

- [ ] **Step 1: Add new check tests to tests/test_checks.py**

Append to `tests/test_checks.py`:

```python
import json
from checks import (
    check_iam_admin_policy_users,
    check_iam_wildcard_trust,
    check_sg_all_traffic_open,
    check_public_ec2_in_public_subnet,
    check_cloudtrail_log_validation,
    check_guardduty_enabled,
    check_config_enabled,
    check_s3_access_logging,
)


# ── IAM: admin policy on user ────────────────────────────────────────────────

@mock_aws
def test_check_iam_admin_policy_users_clean():
    session = boto3.Session(region_name="us-east-1")
    findings = check_iam_admin_policy_users(session)
    assert findings == []


@mock_aws
def test_check_iam_admin_policy_users_finds_direct_admin():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="baduser")
    iam.attach_user_policy(
        UserName="baduser",
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
    )
    session = boto3.Session(region_name="us-east-1")
    findings = check_iam_admin_policy_users(session)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["check"] == "iam_admin_policy_on_user"
    assert "baduser" in findings[0]["resource"]


# ── IAM: wildcard trust policy ───────────────────────────────────────────────

@mock_aws
def test_check_iam_wildcard_trust_clean():
    iam = boto3.client("iam", region_name="us-east-1")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
    })
    iam.create_role(RoleName="safe-role", AssumeRolePolicyDocument=trust)
    session = boto3.Session(region_name="us-east-1")
    findings = check_iam_wildcard_trust(session)
    assert findings == []


@mock_aws
def test_check_iam_wildcard_trust_finds_wildcard():
    iam = boto3.client("iam", region_name="us-east-1")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
    })
    iam.create_role(RoleName="dangerous-role", AssumeRolePolicyDocument=trust)
    session = boto3.Session(region_name="us-east-1")
    findings = check_iam_wildcard_trust(session)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["check"] == "iam_wildcard_trust_policy"


# ── Network: all-traffic SG ───────────────────────────────────────────────────

@mock_aws
def test_check_sg_all_traffic_open_clean():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.create_security_group(GroupName="safe-sg", Description="safe")
    session = boto3.Session(region_name="us-east-1")
    findings = check_sg_all_traffic_open(session)
    assert findings == []


@mock_aws
def test_check_sg_all_traffic_open_finds_wildcard_protocol():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="open-sg", Description="open")
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    session = boto3.Session(region_name="us-east-1")
    findings = check_sg_all_traffic_open(session)
    assert len(findings) >= 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["check"] == "sg_all_traffic_open"


# ── Network: public EC2 in public subnet ─────────────────────────────────────

@mock_aws
def test_check_public_ec2_in_public_subnet_clean():
    session = boto3.Session(region_name="us-east-1")
    findings = check_public_ec2_in_public_subnet(session)
    assert findings == []


@mock_aws
def test_check_public_ec2_in_public_subnet_finds_exposed_instance():
    ec2 = boto3.client("ec2", region_name="us-east-1")

    # Create VPC + IGW + public subnet
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]
    igw = ec2.create_internet_gateway()
    igw_id = igw["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")
    subnet_id = subnet["Subnet"]["SubnetId"]

    rt = ec2.create_route_table(VpcId=vpc_id)
    rt_id = rt["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)

    # Launch instance with public IP in public subnet
    ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        NetworkInterfaces=[{
            "DeviceIndex": 0,
            "SubnetId": subnet_id,
            "AssociatePublicIpAddress": True,
        }],
    )

    session = boto3.Session(region_name="us-east-1")
    findings = check_public_ec2_in_public_subnet(session)
    assert len(findings) >= 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["check"] == "public_ec2_in_public_subnet"


# ── IR: CloudTrail log validation ────────────────────────────────────────────

@mock_aws
def test_check_cloudtrail_log_validation_clean():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="trail-bucket")
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    ct.create_trail(
        Name="my-trail",
        S3BucketName="trail-bucket",
        EnableLogFileValidation=True,
    )
    session = boto3.Session(region_name="us-east-1")
    findings = check_cloudtrail_log_validation(session)
    assert findings == []


@mock_aws
def test_check_cloudtrail_log_validation_finds_disabled_validation():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="trail-bucket")
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    ct.create_trail(
        Name="my-trail",
        S3BucketName="trail-bucket",
        EnableLogFileValidation=False,
    )
    session = boto3.Session(region_name="us-east-1")
    findings = check_cloudtrail_log_validation(session)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["check"] == "cloudtrail_log_validation_disabled"


# ── IR: GuardDuty enabled ────────────────────────────────────────────────────

@mock_aws
def test_check_guardduty_enabled_clean():
    gd = boto3.client("guardduty", region_name="us-east-1")
    gd.create_detector(Enable=True)
    session = boto3.Session(region_name="us-east-1")
    findings = check_guardduty_enabled(session)
    assert findings == []


@mock_aws
def test_check_guardduty_enabled_finds_no_detector():
    session = boto3.Session(region_name="us-east-1")
    findings = check_guardduty_enabled(session)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["check"] == "guardduty_not_enabled"


# ── Compliance: AWS Config ────────────────────────────────────────────────────

@mock_aws
def test_check_config_enabled_clean():
    cfg = boto3.client("config", region_name="us-east-1")
    cfg.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": "arn:aws:iam::123456789012:role/config-role",
        }
    )
    cfg.start_configuration_recorder(ConfigurationRecorderName="default")
    session = boto3.Session(region_name="us-east-1")
    findings = check_config_enabled(session)
    assert findings == []


@mock_aws
def test_check_config_enabled_finds_no_recorder():
    session = boto3.Session(region_name="us-east-1")
    findings = check_config_enabled(session)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["check"] == "config_not_enabled"


# ── Compliance: S3 access logging ────────────────────────────────────────────

@mock_aws
def test_check_s3_access_logging_clean():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="logged-bucket")
    s3.create_bucket(Bucket="log-dest-bucket")
    s3.put_bucket_logging(
        Bucket="logged-bucket",
        BucketLoggingStatus={
            "LoggingEnabled": {"TargetBucket": "log-dest-bucket", "TargetPrefix": "logs/"}
        },
    )
    session = boto3.Session(region_name="us-east-1")
    findings = check_s3_access_logging(session)
    assert all(f["resource"] != "s3://logged-bucket" for f in findings)


@mock_aws
def test_check_s3_access_logging_finds_unlogged_bucket():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="silent-bucket")
    session = boto3.Session(region_name="us-east-1")
    findings = check_s3_access_logging(session)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["check"] == "s3_access_logging_disabled"
    assert findings[0]["resource"] == "s3://silent-bucket"
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_checks.py -v -k "not test_run_all and not test_severity"
```

Expected: all new tests FAIL (stub functions return `[]`).

- [ ] **Step 3: Implement 8 new check functions in checks.py**

Replace each stub function in `checks.py` with its real implementation:

```python
def check_iam_admin_policy_users(session):
    findings = []
    iam = session.client("iam")
    try:
        users = iam.list_users().get("Users", [])
        for user in users:
            username = user["UserName"]
            policies = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
            for policy in policies:
                if policy["PolicyArn"] == "arn:aws:iam::aws:policy/AdministratorAccess":
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
```

- [ ] **Step 4: Run new check tests**

```bash
pytest tests/test_checks.py -v
```

Expected: all 21+ tests PASS.

- [ ] **Step 5: Commit**

```bash
git add checks.py tests/test_checks.py
git commit -m "feat: add 8 new checks covering all Security+ domains (IAM, Network, IR, Compliance)"
```

---

## Task 3: Compliance Scoring

**Files:**
- Modify: `compliance.py` (replace stub with full implementation)
- Create: `tests/test_compliance.py`

**Interfaces:**
- Consumes: `list[tuple[str, list[dict]]]` from `checks.run_all_checks`
- Produces: `compute_compliance(check_results) -> dict` with keys `cis_aws_v2` and `nist_csf_coverage`

- [ ] **Step 1: Write failing tests**

Create `tests/test_compliance.py`:

```python
from compliance import compute_compliance


def _make_results(passing_names: list[str], failing_names: list[str]) -> list[tuple[str, list[dict]]]:
    results = []
    for name in passing_names:
        results.append((name, []))
    for name in failing_names:
        results.append((name, [{"resource": "r", "check": "c", "severity": "HIGH", "detail": "d", "remediation": "r"}]))
    return results


def test_all_passing_gives_100_percent():
    from checks import ALL_CHECK_FUNCTIONS
    results = [(fn.__name__, []) for fn in ALL_CHECK_FUNCTIONS]
    scores = compute_compliance(results)
    assert scores["cis_aws_v2"]["score_pct"] == 100
    assert scores["cis_aws_v2"]["passing"] == 19
    assert scores["cis_aws_v2"]["total"] == 19


def test_all_failing_gives_0_percent():
    from checks import ALL_CHECK_FUNCTIONS
    dummy_finding = [{"resource": "r", "check": "c", "severity": "HIGH", "detail": "d", "remediation": "r"}]
    results = [(fn.__name__, dummy_finding) for fn in ALL_CHECK_FUNCTIONS]
    scores = compute_compliance(results)
    assert scores["cis_aws_v2"]["score_pct"] == 0
    assert scores["cis_aws_v2"]["passing"] == 0


def test_partial_compliance_score():
    from checks import ALL_CHECK_FUNCTIONS
    dummy_finding = [{"resource": "r", "check": "c", "severity": "HIGH", "detail": "d", "remediation": "r"}]
    # First 10 pass, last 9 fail
    results = [(fn.__name__, []) for fn in ALL_CHECK_FUNCTIONS[:10]]
    results += [(fn.__name__, dummy_finding) for fn in ALL_CHECK_FUNCTIONS[10:]]
    scores = compute_compliance(results)
    assert scores["cis_aws_v2"]["passing"] == 10
    assert scores["cis_aws_v2"]["total"] == 19
    assert scores["cis_aws_v2"]["score_pct"] == round(10 / 19 * 100)


def test_nist_identify_counts_correct_checks():
    from checks import ALL_CHECK_FUNCTIONS
    results = [(fn.__name__, []) for fn in ALL_CHECK_FUNCTIONS]
    scores = compute_compliance(results)
    identify = scores["nist_csf_coverage"]["identify"]
    assert identify["total"] == 3
    assert identify["passing"] == 3


def test_nist_protect_counts_correct_checks():
    from checks import ALL_CHECK_FUNCTIONS
    results = [(fn.__name__, []) for fn in ALL_CHECK_FUNCTIONS]
    scores = compute_compliance(results)
    protect = scores["nist_csf_coverage"]["protect"]
    assert protect["total"] == 11


def test_nist_detect_counts_correct_checks():
    from checks import ALL_CHECK_FUNCTIONS
    results = [(fn.__name__, []) for fn in ALL_CHECK_FUNCTIONS]
    scores = compute_compliance(results)
    detect = scores["nist_csf_coverage"]["detect"]
    assert detect["total"] == 5


def test_nist_respond_is_informational_string():
    from checks import ALL_CHECK_FUNCTIONS
    results = [(fn.__name__, []) for fn in ALL_CHECK_FUNCTIONS]
    scores = compute_compliance(results)
    assert scores["nist_csf_coverage"]["respond"] == "covered by LLM playbooks"


def test_nist_recover_is_none():
    from checks import ALL_CHECK_FUNCTIONS
    results = [(fn.__name__, []) for fn in ALL_CHECK_FUNCTIONS]
    scores = compute_compliance(results)
    assert scores["nist_csf_coverage"]["recover"] is None


def test_failing_identify_check_reduces_nist_score():
    from checks import ALL_CHECK_FUNCTIONS
    dummy_finding = [{"resource": "r", "check": "c", "severity": "MEDIUM", "detail": "d", "remediation": "r"}]
    # Make check_config_enabled fail (it's in Identify)
    results = []
    for fn in ALL_CHECK_FUNCTIONS:
        if fn.__name__ == "check_config_enabled":
            results.append((fn.__name__, dummy_finding))
        else:
            results.append((fn.__name__, []))
    scores = compute_compliance(results)
    identify = scores["nist_csf_coverage"]["identify"]
    assert identify["passing"] == 2  # 3 total, 1 failing
    assert identify["total"] == 3
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_compliance.py -v
```

Expected: all tests FAIL (stub returns zeros).

- [ ] **Step 3: Implement compliance.py**

Replace `compliance.py` with:

```python
"""CIS AWS Foundations Benchmark v2 + NIST CSF compliance scoring."""

NIST_MAPPING: dict[str, list[str]] = {
    "identify": [
        "check_config_enabled",
        "check_vpc_flow_logs",
        "check_s3_access_logging",
    ],
    "protect": [
        "check_iam_admin_policy_users",
        "check_iam_wildcard_trust",
        "check_root_access_key",
        "check_mfa_root",
        "check_iam_password_policy",
        "check_unused_access_keys",
        "check_unencrypted_ebs",
        "check_s3_encryption",
        "check_open_ssh_rdp",
        "check_sg_all_traffic_open",
        "check_public_ec2_in_public_subnet",
    ],
    "detect": [
        "check_guardduty_enabled",
        "check_cloudtrail_disabled",
        "check_cloudtrail_log_validation",
        "check_public_s3_buckets",
        "check_public_rds",
    ],
}


def compute_compliance(check_results: list[tuple[str, list[dict]]]) -> dict:
    """
    check_results: list of (check_function_name, findings) from run_all_checks().
    Returns compliance_scores dict consumed by reporter.py.
    """
    passed_checks = {name for name, findings in check_results if not findings}
    total = len(check_results)
    passing = len(passed_checks)

    cis_score = {
        "passing": passing,
        "total": total,
        "score_pct": round(passing / total * 100) if total else 0,
    }

    nist_coverage: dict[str, object] = {}
    for function, check_names in NIST_MAPPING.items():
        func_total = len(check_names)
        func_passing = sum(1 for c in check_names if c in passed_checks)
        nist_coverage[function] = {"passing": func_passing, "total": func_total}

    nist_coverage["respond"] = "covered by LLM playbooks"
    nist_coverage["recover"] = None

    return {
        "cis_aws_v2": cis_score,
        "nist_csf_coverage": nist_coverage,
    }
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_compliance.py -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add compliance.py tests/test_compliance.py
git commit -m "feat: add CIS/NIST compliance scoring"
```

---

## Task 4: LLM Remediation Engine

**Files:**
- Modify: `llm_remediation.py` (replace stub with full implementation)
- Create: `tests/test_llm.py`

**Interfaces:**
- Consumes: `findings: list[dict]`, `api_key: str`
- Produces: `enrich_with_playbooks(findings, api_key) -> list[dict]` — same list with `playbook` dict added to each finding

- [ ] **Step 1: Write failing tests**

Create `tests/test_llm.py`:

```python
import json
from unittest.mock import MagicMock, patch

from llm_remediation import enrich_with_playbooks, _build_playbook_prompt

SAMPLE_FINDING = {
    "resource": "s3://my-bucket",
    "check": "public_s3_bucket",
    "severity": "CRITICAL",
    "detail": "Bucket ACL grants access to AllUsers.",
    "remediation": "Remove public ACL grants.",
}

SAMPLE_PLAYBOOK = {
    "immediate_steps": ["aws s3api put-public-access-block --bucket my-bucket --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"],
    "verification": "aws s3api get-public-access-block --bucket my-bucket",
    "long_term_controls": ["Enable S3 Block Public Access at account level", "Add Config rule s3-bucket-public-read-prohibited"],
    "blast_radius": "Any unauthenticated user can list and download all bucket contents.",
}


def test_enrich_adds_playbook_field():
    mock_client = MagicMock()
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=json.dumps(SAMPLE_PLAYBOOK))]
    mock_client.messages.create.return_value = mock_message

    with patch("llm_remediation.anthropic.Anthropic", return_value=mock_client):
        result = enrich_with_playbooks([SAMPLE_FINDING.copy()], api_key="test-key")

    assert "playbook" in result[0]
    pb = result[0]["playbook"]
    assert "immediate_steps" in pb
    assert "verification" in pb
    assert "long_term_controls" in pb
    assert "blast_radius" in pb


def test_enrich_caches_by_check_name():
    """Same check type on two findings → only one API call."""
    mock_client = MagicMock()
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=json.dumps(SAMPLE_PLAYBOOK))]
    mock_client.messages.create.return_value = mock_message

    findings = [SAMPLE_FINDING.copy(), {**SAMPLE_FINDING.copy(), "resource": "s3://other-bucket"}]

    with patch("llm_remediation.anthropic.Anthropic", return_value=mock_client):
        result = enrich_with_playbooks(findings, api_key="test-key")

    assert mock_client.messages.create.call_count == 1
    assert result[0]["playbook"] == result[1]["playbook"]


def test_enrich_different_checks_call_api_separately():
    """Two different check types → two API calls."""
    mock_client = MagicMock()
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=json.dumps(SAMPLE_PLAYBOOK))]
    mock_client.messages.create.return_value = mock_message

    finding_a = SAMPLE_FINDING.copy()
    finding_b = {**SAMPLE_FINDING.copy(), "check": "guardduty_not_enabled"}

    with patch("llm_remediation.anthropic.Anthropic", return_value=mock_client):
        enrich_with_playbooks([finding_a, finding_b], api_key="test-key")

    assert mock_client.messages.create.call_count == 2


def test_enrich_preserves_all_original_fields():
    mock_client = MagicMock()
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=json.dumps(SAMPLE_PLAYBOOK))]
    mock_client.messages.create.return_value = mock_message

    finding = SAMPLE_FINDING.copy()
    with patch("llm_remediation.anthropic.Anthropic", return_value=mock_client):
        result = enrich_with_playbooks([finding], api_key="test-key")

    for key in ["resource", "check", "severity", "detail", "remediation"]:
        assert result[0][key] == SAMPLE_FINDING[key]


def test_enrich_gracefully_handles_invalid_json_response():
    """Malformed API response → finding has no playbook field, no crash."""
    mock_client = MagicMock()
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text="not valid json {{")]
    mock_client.messages.create.return_value = mock_message

    with patch("llm_remediation.anthropic.Anthropic", return_value=mock_client):
        result = enrich_with_playbooks([SAMPLE_FINDING.copy()], api_key="test-key")

    assert "playbook" not in result[0]


def test_build_playbook_prompt_contains_check_name():
    prompt = _build_playbook_prompt(SAMPLE_FINDING)
    assert "public_s3_bucket" in prompt
    assert "CRITICAL" in prompt
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_llm.py -v
```

Expected: FAIL (`ImportError` or assertion failures from stub).

- [ ] **Step 3: Implement llm_remediation.py**

Replace `llm_remediation.py` with:

```python
"""LLM-powered remediation playbook engine using Claude Haiku."""

import json

import anthropic

MODEL = "claude-haiku-4-5-20251001"

SYSTEM_PROMPT = (
    "You are a senior cloud security engineer with deep AWS expertise. "
    "Given an AWS security finding, return a JSON remediation playbook with exactly "
    "these four fields:\n"
    "  - immediate_steps: ordered list of AWS CLI commands or console steps to fix now\n"
    "  - verification: single string — how to confirm the fix worked\n"
    "  - long_term_controls: list of preventive controls to stop recurrence (SCP, Config rule, policy)\n"
    "  - blast_radius: single string — what an attacker could do if this finding is not fixed\n\n"
    "Return only valid JSON. No prose outside the JSON object."
)


def _build_playbook_prompt(finding: dict) -> str:
    return (
        f"Finding:\n"
        f"  Check: {finding['check']}\n"
        f"  Severity: {finding['severity']}\n"
        f"  Resource: {finding['resource']}\n"
        f"  Detail: {finding['detail']}\n"
        f"  Current remediation hint: {finding['remediation']}"
    )


def enrich_with_playbooks(findings: list[dict], api_key: str) -> list[dict]:
    """
    Add 'playbook' field to each finding via Claude Haiku.
    Caches by check name — one API call per unique check type.
    """
    client = anthropic.Anthropic(api_key=api_key)
    cache: dict[str, dict] = {}
    enriched = []

    for finding in findings:
        check_name = finding["check"]
        finding = finding.copy()

        if check_name not in cache:
            try:
                message = client.messages.create(
                    model=MODEL,
                    max_tokens=1024,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": _build_playbook_prompt(finding)}],
                )
                raw = message.content[0].text
                cache[check_name] = json.loads(raw)
            except (json.JSONDecodeError, Exception):
                cache[check_name] = None

        if cache[check_name] is not None:
            finding["playbook"] = cache[check_name]

        enriched.append(finding)

    return enriched
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_llm.py -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add llm_remediation.py tests/test_llm.py
git commit -m "feat: add LLM remediation playbook engine (Claude Haiku, cached by check type)"
```

---

## Task 5: Full Test Suite + Integration Smoke Test

**Files:**
- Modify: `tests/test_checks.py` (add integration test for run_all_checks return shape)
- Modify: `scanner.py` (verify --llm wiring end-to-end)

**Interfaces:**
- Consumes: all modules from Tasks 1–4
- Produces: full `pytest` suite passing, `scanner.py --help` shows `--llm` flag

- [ ] **Step 1: Add end-to-end integration test**

Append to `tests/test_checks.py`:

```python
from compliance import compute_compliance


@mock_aws
def test_full_pipeline_produces_valid_compliance_scores():
    """run_all_checks → compute_compliance → valid score structure."""
    session = boto3.Session(region_name="us-east-1")
    check_results = run_all_checks(session, verbose=False)
    scores = compute_compliance(check_results)

    assert "cis_aws_v2" in scores
    assert "nist_csf_coverage" in scores
    cis = scores["cis_aws_v2"]
    assert 0 <= cis["score_pct"] <= 100
    assert cis["total"] == 19

    nist = scores["nist_csf_coverage"]
    for fn in ["identify", "protect", "detect"]:
        assert isinstance(nist[fn], dict)
        assert "passing" in nist[fn]
        assert "total" in nist[fn]
```

- [ ] **Step 2: Run full test suite**

```bash
pytest tests/ -v
```

Expected: all tests PASS. Count should be 30+.

- [ ] **Step 3: Verify CLI help shows --llm**

```bash
python scanner.py --help
```

Expected output includes:
```
  --llm    Generate LLM remediation playbooks
```

- [ ] **Step 4: Commit**

```bash
git add tests/test_checks.py
git commit -m "test: add integration test for full pipeline (checks → compliance scoring)"
```

---

## Task 6: Documentation

**Files:**
- Modify: `DESIGN.md`
- Modify: `README.md`
- Create: `docs/SECURITY_DOMAINS.md`
- Create: `docs/PRODUCT_DECISIONS.md`

**Interfaces:**
- No code interfaces — these are PM artifacts

- [ ] **Step 1: Update DESIGN.md**

Append after the existing "What's Next and Why" section:

```markdown
---

## New Checks — Why These 8 (v2)

| Tier | Check | Security+ Domain | Rationale |
|------|-------|-----------------|-----------|
| **Ship now** | IAM admin policy on users | A — Identity | Violates least privilege. Direct policy attachment creates ungovernable blast radius. Removing it costs zero operational impact; not removing it costs the ability to govern access at scale. |
| **Ship now** | IAM wildcard trust policy | A — Identity | `Principal: *` = any entity in the world can assume the role. No credentials required if there are no condition constraints. CRITICAL because it's the kind of misconfiguration that gets created by a confused dev and never reviewed. |
| **Ship now** | All-traffic security group | B — Network | Protocol `-1` + `0.0.0.0/0` is worse than open SSH/RDP — it exposes every port. Wiz's 2024 State of Cloud Security report lists this as the #1 finding in enterprise scans. |
| **Ship now** | Public EC2 in public subnet | B — Network | Not CRITICAL alone, but creates the attack surface that other findings exploit. Public IP + open SG = full exposure. Flagging at MEDIUM enables a compound-risk narrative. |
| **Ship now** | CloudTrail log validation | C — IR/Forensics | Enabled ≠ trustworthy. Without log file validation, an attacker can delete/modify trail logs post-breach. The difference between "we have evidence" and "we have nothing." |
| **Ship now** | GuardDuty not enabled | C — IR/Forensics | Real-time threat detection layer. If CloudTrail is the audit log, GuardDuty is the alarm. Neither replaces the other. $0 setup cost with significant IR value. |
| **Ship now** | AWS Config not enabled | D — Compliance/Risk | Without Config, you cannot answer "what was the state of this resource at the time of the breach?" Required for SOC 2, PCI, and any compliance audit. |
| **Ship now** | S3 access logging disabled | D — Compliance/Risk | CloudTrail captures control-plane API calls. S3 access logging captures data-plane GET/PUT/DELETE. Both are needed for full data exfiltration forensics. |

---

## LLM Remediation Playbooks

**Why opt-in:** CSPM tools don't know what a user's specific account looks like. The most useful remediation advice is environment-specific. Opt-in via `--llm` + `ANTHROPIC_API_KEY` keeps costs at zero for users who don't need it.

**Why Haiku, not Sonnet:** Remediation steps are structured and formulaic. Haiku's output quality is indistinguishable from Sonnet for this task at ~10x lower cost. If a future version adds complex IAM privilege escalation chain analysis, that specific step can promote to Sonnet while routine playbooks stay on Haiku.

**Why cache by check name:** The playbook for `public_s3_bucket` doesn't change based on which bucket triggered it. Resource-specific context doesn't improve the playbook — it adds cost and latency. 19 unique check types = maximum 19 API calls regardless of account size.

**Cost model:** 19 checks × ~500 tokens each ≈ $0.01 per full scan with `--llm`. Noted in README. Opt-in framing means this is never a surprise.

**Playbook fields — why these four:**
- `immediate_steps` — the thing the on-call engineer does right now
- `verification` — closes the loop; most CSPM tools skip this entirely
- `long_term_controls` — the platform engineering angle: prevent, don't just fix
- `blast_radius` — forces the reader to understand the stakes before deprioritizing

---

## Compliance Scoring

**Why CIS AWS Foundations Benchmark v2:** Already partially referenced in v1. SOC 2 auditors, PCI QSAs, and enterprise procurement teams reference it. Provides a defensible scope boundary. CIS gives credibility with security buyers.

**Why NIST CSF (informational, not scored):** Five-function framework (Identify/Protect/Detect/Respond/Recover) used by Wiz, Lacework, and AWS Security Hub in enterprise reporting. Shows risk management thinking beyond a checklist. Presented as informational — not scored — because checks overlap across functions, and scoring overlapping categories produces double-counting artifacts that mislead more than they inform.

**Why not MITRE ATT&CK:** Threat modeling framework, not a posture benchmark. Useful for detection engineering, wrong lens for misconfiguration scanning.

**Why simple scoring (not weighted):** Weighted scoring (CRITICAL failures count more) would be more accurate but harder to explain to a non-technical stakeholder. The score's job is communication, not precision. A PM decision.
```

- [ ] **Step 2: Update README.md**

Replace the "What It Detects" table and "Roadmap" section with:

```markdown
## What It Detects

| Check | Severity | CIS Benchmark | Security+ Domain |
|---|---|---|---|
| Public S3 buckets (ACL or policy) | 🔴 CRITICAL | CIS AWS 2.1.5 | A — Identity |
| Public RDS instances | 🔴 CRITICAL | — | B — Network |
| Root account access key active | 🔴 CRITICAL | CIS AWS 1.4 | A — Identity |
| IAM role with wildcard trust policy | 🔴 CRITICAL | CIS AWS 1.16 | A — Identity |
| Security group with ALL traffic open | 🔴 CRITICAL | CIS AWS 5.1 | B — Network |
| Security groups open SSH/RDP to 0.0.0.0/0 | 🟠 HIGH | CIS AWS 5.2, 5.3 | B — Network |
| Root account MFA not enabled | 🟠 HIGH | CIS AWS 1.5 | A — Identity |
| IAM users with console password, no MFA | 🟠 HIGH | CIS AWS 1.10 | A — Identity |
| Unused IAM access keys (>90 days) | 🟠 HIGH | CIS AWS 1.12 | A — Identity |
| IAM users with direct admin policy | 🟠 HIGH | CIS AWS 1.16 | A — Identity |
| CloudTrail log file validation disabled | 🟠 HIGH | CIS AWS 3.2 | C — IR/Forensics |
| GuardDuty not enabled | 🟠 HIGH | — | C — IR/Forensics |
| Unencrypted EBS volumes | 🟡 MEDIUM | CIS AWS 2.2.1 | A — Identity |
| IAM password policy gaps | 🟡 MEDIUM | CIS AWS 1.8–1.9 | A — Identity |
| S3 default encryption not enabled | 🟡 MEDIUM | CIS AWS 2.1.1 | A — Identity |
| VPC flow logs not enabled | 🟡 MEDIUM | CIS AWS 3.9 | D — Compliance |
| CloudTrail not enabled | 🟡 MEDIUM | CIS AWS 3.1 | C — IR/Forensics |
| EC2 instances with public IP in public subnet | 🟡 MEDIUM | CIS AWS 5.6 | B — Network |
| AWS Config not enabled | 🟡 MEDIUM | CIS AWS 3.5 | D — Compliance |
| S3 access logging disabled | 🟡 MEDIUM | CIS AWS 2.1.4 | D — Compliance |

## Usage

```bash
pip install -r requirements.txt
python scanner.py                              # default AWS profile, us-east-1
python scanner.py my-profile us-west-2        # named profile + region
python scanner.py --llm                        # add LLM remediation playbooks (requires ANTHROPIC_API_KEY)
python scanner.py my-profile us-east-1 --llm  # full options
```

**LLM mode cost:** ~$0.01 per full scan (19 unique check types × ~500 tokens × claude-haiku-4-5 pricing). Opt-in only.
```

- [ ] **Step 3: Create docs/SECURITY_DOMAINS.md**

```markdown
# CloudWatchdog — Security+ Domain Coverage Map

Maps every check to a Security+ SY0-701 exam objective, CIS AWS Foundations Benchmark v2 control,
and the real-world incident or breach pattern that motivates the check.

Use this document to walk through the security thinking behind the tool in interviews or portfolio reviews.

---

## Domain A — Identity and Access Management (Security+ Obj 3.7)

### public_s3_bucket — CRITICAL
- **CIS:** 2.1.5
- **Breach pattern:** Capital One 2019 (SSRF → misconfigured S3), Twitch 2021 (overly permissive S3). Public S3 is the most frequently cited cloud data exposure vector.
- **Why CRITICAL:** No credentials required. Data is exposed the moment the ACL is set.

### root_access_key_active — CRITICAL
- **CIS:** 1.4
- **Breach pattern:** Root key compromise = full account takeover, no restrictions. AWS explicitly states root keys should never exist. Common in accounts set up by solo developers.
- **Why CRITICAL:** Root has no permission boundaries. If the key leaks, the account is owned.

### iam_wildcard_trust_policy — CRITICAL
- **CIS:** 1.16
- **Breach pattern:** Overpermissive cross-account trust. An attacker with any AWS account can call sts:AssumeRole if Principal is `*` with no conditions.
- **Why CRITICAL:** No attacker prep required beyond having an AWS account.

### root_mfa_not_enabled — HIGH
- **CIS:** 1.5
- **Breach pattern:** Phished root credentials. Root console login without MFA = game over.
- **Why HIGH:** Requires phishing or credential theft first (one step).

### iam_user_mfa_not_enabled — HIGH
- **CIS:** 1.10
- **Breach pattern:** Credential stuffing against IAM console users. Common in organizations where developers use personal IAM users.
- **Why HIGH:** Credential theft is the first step; MFA blocks escalation.

### iam_admin_policy_on_user — HIGH
- **CIS:** 1.16
- **Breach pattern:** Over-permissioned developer accounts. If a developer's access key leaks, AdministratorAccess on their user = full account compromise.
- **Why HIGH:** Requires key theft first. But blast radius is maximum.

### unused_iam_access_key — HIGH
- **CIS:** 1.12
- **Breach pattern:** Stale credentials in leaked config files, CI/CD logs, or old repos. Keys active for 90+ days with no use are forgotten and thus never monitored.
- **Why HIGH:** If stolen, they go undetected indefinitely (no baseline activity to alert on).

### iam_password_policy_missing / iam_password_policy_weak — MEDIUM
- **CIS:** 1.8–1.9
- **Breach pattern:** Weak passwords + credential stuffing. Common in orgs that rely on IAM users for human access.
- **Why MEDIUM:** Requires password guessing/stuffing; no direct exploit today.

### unencrypted_ebs_volume — MEDIUM
- **CIS:** 2.2.1
- **Breach pattern:** Physical/hypervisor-level access at AWS (extremely unlikely) or snapshot leaks. Relevant for compliance (SOC 2, HIPAA, PCI).
- **Why MEDIUM:** Requires infrastructure-level access to exploit; compliance gap today.

---

## Domain B — Network Security (Security+ Obj 3.3)

### sg_all_traffic_open — CRITICAL
- **CIS:** 5.1
- **Breach pattern:** Protocol `-1` + `0.0.0.0/0` exposes every port. Often created as "temporary" rules during development. Wiz 2024 State of Cloud Security: #1 finding in enterprise scans.
- **Why CRITICAL:** No attacker prep needed. Every port is open.

### open_ssh_rdp_to_world — HIGH
- **CIS:** 5.2, 5.3
- **Breach pattern:** Brute force SSH, credential stuffing RDP. Most common direct attack vector against compute.
- **Why HIGH:** Requires brute force or stolen credentials first (one step).

### public_rds_instance — CRITICAL
- **CIS:** 2.3.2 (equiv.)
- **Breach pattern:** Database port directly exposed. No network boundary between attacker and data.
- **Why CRITICAL:** Direct path to data exfiltration if any DB credential is weak or reused.

### public_ec2_in_public_subnet — MEDIUM
- **CIS:** 5.6
- **Breach pattern:** Compound risk — EC2 in public subnet with public IP + open SG = fully exposed instance. Neither condition is CRITICAL alone; together they are.
- **Why MEDIUM:** The IP alone doesn't mean exploitation; requires weak/open security group as well.

---

## Domain C — Incident Response and Forensics (Security+ Obj 4.3)

### cloudtrail_not_enabled — MEDIUM
- **CIS:** 3.1
- **Breach pattern:** No audit log of API calls. You cannot perform forensics on an incident you can't see.
- **Why MEDIUM:** Doesn't cause a breach, but prevents detecting one.

### cloudtrail_log_validation_disabled — HIGH
- **CIS:** 3.2
- **Breach pattern:** Post-breach log tampering. An attacker with S3 write access can delete trail logs to erase evidence. Log file validation creates a cryptographic chain that detects tampering.
- **Why HIGH:** One step from exploitation: attacker needs S3 write access (already a HIGH finding if present).

### guardduty_not_enabled — HIGH
- **CIS:** (no direct CIS control — GuardDuty is AWS-native)
- **Breach pattern:** Undetected cryptomining, exfiltration, C2 traffic. GuardDuty watches CloudTrail, VPC flow logs, and DNS for anomalous patterns in real time.
- **Why HIGH:** Without it, you're reactive not proactive. Every incident starts later.

---

## Domain D — Risk Management and Compliance (Security+ Obj 5.1)

### config_not_enabled — MEDIUM
- **CIS:** 3.5
- **Breach pattern:** Missing configuration history. Cannot answer "what was the state of this resource at the time of the breach?" Required for SOC 2 Type II and PCI DSS audits.
- **Why MEDIUM:** Not exploitable directly; forensics and compliance gap.

### vpc_flow_logs_disabled — MEDIUM
- **CIS:** 3.9
- **Breach pattern:** No network telemetry. Cannot detect anomalous traffic patterns, lateral movement, or data exfiltration via network analysis.
- **Why MEDIUM:** Reduces detection capability; not directly exploitable.

### s3_access_logging_disabled — MEDIUM
- **CIS:** 2.1.4
- **Breach pattern:** Undetected data exfiltration. CloudTrail records API calls (control plane); S3 access logging records individual object reads (data plane). Both are needed for full forensics.
- **Why MEDIUM:** Compliance and forensics gap. Not directly exploitable.

### s3_encryption_not_enabled — MEDIUM
- **CIS:** 2.1.1
- **Breach pattern:** Data at rest unprotected if bucket or AWS infrastructure is compromised. Required for HIPAA, PCI, SOC 2.
- **Why MEDIUM:** Exploitation requires infrastructure-level access; compliance gap today.
```

- [ ] **Step 4: Create docs/PRODUCT_DECISIONS.md**

```markdown
# CloudWatchdog — Product Decision Log

PM artifact documenting major design decisions: the context, options considered,
choice made, and the reasoning behind it.

This document is designed to be read in a product or engineering interview.
Each entry answers: "Why did you build it this way?"

---

## Decision 1: Module split (monolith → 4 focused modules)

**Context:** Original `scanner.py` contained detection logic, output rendering, and orchestration in one file. As the check count grew from 11 to 19 and two new capabilities (LLM, compliance) were added, the file would have exceeded 800 lines with multiple distinct responsibilities.

**Options considered:**
1. Keep monolith, add features inline
2. Split by capability (checks.py, compliance.py, llm_remediation.py, reporter.py)
3. Package structure with `__init__.py` and subdirectories

**Decision:** Option 2 — flat module split.

**Rationale:** Option 1 produces an untestable, unmaintainable file. Option 3 adds import complexity with no benefit for a 5-file project. Option 2 gives each file one responsibility, makes each testable in isolation, and keeps the import graph flat. A reviewer can read any single file and understand its purpose without context from the others.

---

## Decision 2: LLM opt-in via --llm flag, not default

**Context:** LLM remediation playbooks are the P0 differentiator. Could have made them default behavior.

**Options considered:**
1. Default on (LLM always runs, fails gracefully if no API key)
2. Opt-in via `--llm` flag + env var
3. Separate command (`python remediate.py`)

**Decision:** Option 2 — opt-in.

**Rationale:** Most runs are CI/CD or ad-hoc ops scans where adding $0.01/scan cost and ~20 seconds of latency is unwanted. Making it default degrades the core use case. Option 3 fragments the UX — users would have to run two commands for one workflow. Opt-in preserves zero-cost operation for all users while making the feature discoverable via `--help`.

---

## Decision 3: Claude Haiku over Sonnet for playbook generation

**Context:** Anthropic offers multiple model tiers. Sonnet is more capable but ~10x more expensive.

**Options considered:**
1. claude-sonnet-4-6: higher reasoning, more expensive
2. claude-haiku-4-5-20251001: fast, cheap, sufficient for structured output

**Decision:** Haiku.

**Rationale:** Remediation playbook fields (immediate_steps, verification, long_term_controls, blast_radius) are structured and formulaic. The task is "fill four JSON fields given a well-defined finding schema" — not multi-step reasoning, not novel synthesis. Haiku's output quality is indistinguishable from Sonnet for this specific task at ~10x lower cost. If future versions add IAM privilege escalation chain analysis (multi-hop reasoning), that specific step can be promoted to Sonnet selectively.

---

## Decision 4: Cache LLM playbooks by check name, not resource

**Context:** An account with 40 unencrypted EBS volumes would generate 40 identical API calls without caching.

**Options considered:**
1. No caching — fresh call per finding
2. Cache by check name — one call per unique check type
3. Cache by (check_name, severity) — slightly more granular
4. Pre-generate all 19 playbooks upfront, regardless of findings

**Decision:** Option 2 — cache by check name.

**Rationale:** Option 1 is expensive and slow at scale. Option 3 adds no value — severity doesn't change the remediation steps. Option 4 wastes money generating playbooks for checks that pass. Option 2 is the minimum cache key that eliminates redundancy: the playbook for `public_s3_bucket` is correct for any bucket that triggers it, regardless of bucket name. Resource-specific context (bucket name, region) would marginally improve specificity at the cost of making caching impossible.

---

## Decision 5: CIS scored, NIST informational (not scored)

**Context:** Two compliance frameworks are surfaced. Scoring both seemed natural.

**Options considered:**
1. Score both CIS and NIST CSF independently
2. Score CIS only; NIST as informational category view
3. Score NIST only (broader framework, better for enterprise)

**Decision:** Option 2 — CIS scored, NIST informational.

**Rationale:** NIST CSF checks overlap across functions. `cloudtrail_not_enabled` serves both Detect (you can't see events) and Respond (you can't investigate events). Scoring overlapping categories produces double-counting: a single check's failure reduces your score in two functions simultaneously, which overstates the problem. CIS controls map 1:1 to checks — no overlap, clean math. NIST's value is the function-level category view, not a score. This is how AWS Security Hub handles NIST mapping in practice.

---

## Decision 6: Simple scoring (not weighted by severity)

**Context:** CRITICAL findings have more blast radius than MEDIUM findings. Weighted scoring would reflect that.

**Options considered:**
1. Weighted: CRITICAL failure counts as -4, HIGH as -3, MEDIUM as -2, LOW as -1
2. Simple: each check is pass/fail, score = passing / total

**Decision:** Option 2 — simple scoring.

**Rationale:** The compliance score is a stakeholder communication tool, not a precision risk metric. A VP of Engineering looking at "74% CIS compliant" has a clear, intuitive frame. "Weighted score 61.2 out of 100" requires explanation of the weighting model, which shifts the conversation from "what do we need to fix" to "how does the score work." Simplicity serves communication. Severity is already surfaced via the findings sort order and severity badges — it doesn't need to be in the score too.

---

## Decision 7: Check selection methodology

**Context:** Hundreds of AWS misconfigurations exist. How to choose 19?

**Framework:** Two filters applied to every candidate check:
1. **Frequency in real breaches** — does this appear in breach post-mortems (Capital One, Twitch, CodeSpaces, etc.)?
2. **Time-to-exploit** — how many attacker steps separate this finding from data exposure or account takeover?

CRITICAL = zero steps. HIGH = one step. MEDIUM = compliance/forensics gap, no current exploit path. LOW = hardening.

**What was excluded and why:**
- Lambda misconfigs: API complexity high, breach frequency lower
- IAM privilege escalation chains: requires graph analysis across policies (future v3 feature)
- Container scanning: different surface area, separate tool category
- Multi-cloud: dilutes AWS depth, wrong v1 scope
- Custom rule builder: wrong user — this is for teams without a dedicated detection engineer

The "scan in 30 seconds, understand in 30 seconds" UX goal was the ultimate scope boundary. Every check that didn't pass that test was deferred.
```

- [ ] **Step 5: Run full test suite one final time**

```bash
pytest tests/ -v
```

Expected: all tests PASS.

- [ ] **Step 6: Final commit**

```bash
git add DESIGN.md README.md docs/SECURITY_DOMAINS.md docs/PRODUCT_DECISIONS.md
git commit -m "docs: add Security+ domain map, PM decision log, update DESIGN.md and README for v2"
```

---

## Self-Review

### Spec Coverage Check

| Spec Requirement | Covered by Task |
|---|---|
| Module split into 4 files | Task 1 |
| checks.py with 19 checks | Tasks 1 + 2 |
| compliance.py CIS scoring | Task 3 |
| compliance.py NIST informational | Task 3 |
| llm_remediation.py Claude Haiku | Task 4 |
| Cache by check name | Task 4 |
| `--llm` CLI flag | Task 1 (scanner.py) |
| Playbook in JSON output | Task 1 (reporter.py) |
| Playbook in HTML (collapsible) | Task 1 (reporter.py) |
| Compliance score in terminal | Task 1 (reporter.py) |
| Compliance score in HTML panel | Task 1 (reporter.py) |
| Compliance score in JSON | Task 1 (reporter.py) |
| DESIGN.md expansion | Task 6 |
| docs/SECURITY_DOMAINS.md | Task 6 |
| docs/PRODUCT_DECISIONS.md | Task 6 |
| README 19-check table | Task 6 |
| All 4 Security+ domains covered | Task 2 |

No gaps found.

### Type Consistency Check

- `run_all_checks` → `list[tuple[str, list[dict]]]` — used in Tasks 1, 3, 4 ✓
- `compute_compliance(check_results)` → `dict` — consumed by `reporter.print_report` ✓
- `enrich_with_playbooks(findings, api_key)` → `list[dict]` — same shape as input + `playbook` field ✓
- `reporter.print_report(findings, compliance_scores)` — both args present in `scanner.run_scan` ✓
- `SEVERITY` dict imported from `checks` in `scanner.py` ✓
