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
