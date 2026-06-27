"""CIS/NIST compliance scoring — implemented in Task 3."""


def compute_compliance(check_results: list[tuple[str, list[dict]]]) -> dict:
    return {
        "cis_aws_v2": {"passing": 0, "total": len(check_results), "score_pct": 0},
        "nist_csf_coverage": {},
    }
