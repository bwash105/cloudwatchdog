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
