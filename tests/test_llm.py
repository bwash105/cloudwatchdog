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
