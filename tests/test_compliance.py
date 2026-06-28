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
    assert scores["cis_aws_v2"]["passing"] == 20
    assert scores["cis_aws_v2"]["total"] == 20


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
    # First 10 pass, last 10 fail
    results = [(fn.__name__, []) for fn in ALL_CHECK_FUNCTIONS[:10]]
    results += [(fn.__name__, dummy_finding) for fn in ALL_CHECK_FUNCTIONS[10:]]
    scores = compute_compliance(results)
    assert scores["cis_aws_v2"]["passing"] == 10
    assert scores["cis_aws_v2"]["total"] == 20
    assert scores["cis_aws_v2"]["score_pct"] == round(10 / 20 * 100)


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
    assert protect["total"] == 12


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
