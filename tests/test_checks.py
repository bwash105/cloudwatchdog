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
