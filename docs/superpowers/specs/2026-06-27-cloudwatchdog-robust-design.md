# CloudWatchdog — Robustness Expansion Design

**Author:** Brian L. E. Washington
**Date:** 2026-06-27
**Status:** Approved for implementation

---

## Problem

CloudWatchdog v0 is a working one-shot CLI scanner with 11 checks and three output formats. It demonstrates CSPM feasibility and PM product thinking. But it has three gaps that limit its value as both a portfolio artifact and a genuinely useful tool:

1. **Incomplete Security+ domain coverage** — checks skew toward IAM/S3. Network, IR/forensics, and compliance/risk management domains are thin.
2. **Static remediation** — every finding gives a generic remediation string. No environment context, no step-by-step playbook, no blast radius analysis. This is the #1 CSPM UX complaint.
3. **No compliance scoring** — no way to tell a stakeholder "you're 74% compliant with CIS AWS Foundations Benchmark." Required for enterprise conversations.

---

## Goal

Evolve CloudWatchdog to a strong L1 CSPM tool that:
- Covers all four Security+ domains with mapped checks
- Generates LLM-powered, environment-specific remediation playbooks (opt-in)
- Produces CIS + NIST compliance scores in every output format
- Ships PM-quality documentation an interviewer at Wiz, Lacework, or CrowdStrike can read and understand product depth

---

## Architecture

### Module Split

Today's `scanner.py` monolith splits into four focused modules:

```
cloudwatchdog/
├── scanner.py          # CLI entrypoint, orchestration, run_scan()
├── checks.py           # all 19 detection rules
├── llm_remediation.py  # Claude API playbook engine
├── compliance.py       # CIS/NIST scoring
└── reporter.py         # terminal + JSON + HTML output
```

**Data flow:**
```
scanner.py
  → checks.py         → findings[]
  → llm_remediation.py → findings[] with playbook field (opt-in)
  → compliance.py     → compliance_scores{}
  → reporter.py       → terminal + cloudwatchdog-report.json + cloudwatchdog-report.html
```

No circular dependencies. Each module has one responsibility and a clear interface. `scanner.py` owns orchestration only — it does not contain detection logic or rendering logic.

### CLI Interface

```bash
python scanner.py                              # default profile, us-east-1
python scanner.py my-profile us-west-2        # named profile + region
python scanner.py --llm                        # enable LLM playbooks (requires ANTHROPIC_API_KEY)
python scanner.py my-profile us-east-1 --llm  # full options
```

---

## Section 1: New Checks — Security+ Domain Coverage

8 new checks added to the existing 11. Total: 19 checks.

Each check is mapped to a Security+ exam objective and a CIS AWS Foundations Benchmark v2 control. This mapping is intentional: every check is defensible to an auditor, an interviewer, and a security buyer.

| Domain | Check | Severity | CIS | Security+ Obj |
|--------|-------|----------|-----|---------------|
| **A — IAM** | IAM users with direct admin policy attached | HIGH | 1.16 | 3.7 |
| **A — IAM** | IAM roles with wildcard trust policy (`"Principal": "*"`) | CRITICAL | 1.16 | 3.7 |
| **B — Network** | Security groups with ALL traffic open (`-1` protocol, `0.0.0.0/0`) | CRITICAL | 5.1 | 3.3 |
| **B — Network** | EC2 instances with auto-assigned public IP in public subnet (public subnet = subnet with active route `0.0.0.0/0 → igw-*`) | MEDIUM | 5.6 | 3.3 |
| **C — IR/Forensics** | CloudTrail log file validation disabled | HIGH | 3.2 | 4.3 |
| **C — IR/Forensics** | GuardDuty not enabled | HIGH | — | 4.3 |
| **D — Compliance** | AWS Config not enabled | MEDIUM | 3.5 | 5.1 |
| **D — Compliance** | S3 access logging disabled | MEDIUM | 2.1.4 | 5.1 |

### Why these 8

**IAM — admin policy on users (CIS 1.16):** Violates least privilege. Users should get permissions through groups or roles, never direct policy attachment. Direct attachment creates a permission audit nightmare — you can't revoke at scale. Maps to Capital One breach pattern: over-permissioned EC2 role that should have been scoped.

**IAM — wildcard trust policy:** A role that trusts `"Principal": "*"` can be assumed by anyone in the world if the role has no condition constraints. CRITICAL because no attacker prep needed — the role hands itself over. Less common than the other CRITICAL checks but catastrophic when present.

**Network — all traffic open SG:** More dangerous than open SSH/RDP. Protocol `-1` + `0.0.0.0/0` = every port exposed to the internet. Often created accidentally ("temporary" rules that never get removed). Wiz's 2024 State of Cloud Security report lists unrestricted security groups as the #1 finding in enterprise scans.

**Network — public IP on EC2 in public subnet:** Not CRITICAL on its own, but in combination with an open SG it becomes the attack path. Flagging it at MEDIUM creates a compound-risk narrative: "this instance has a public IP AND an open SG = full exposure."

**IR — CloudTrail log validation (CIS 3.2):** CloudTrail enabled ≠ CloudTrail trustworthy. Without log file validation, an attacker with S3 write access can delete or modify trail logs after a breach to cover tracks. Required for forensic admissibility. HIGH because it's the difference between "we detected the breach" and "we have no evidence."

**IR — GuardDuty not enabled:** GuardDuty is AWS's managed threat detection layer. Without it, there is no anomaly detection on API calls, DNS queries, or network traffic. If CloudTrail is the audit log, GuardDuty is the real-time alarm. Neither replaces the other. HIGH because it's a $0 setup cost with significant incident response value.

**Compliance — AWS Config not enabled (CIS 3.5):** Config tracks resource state changes over time. Without it, you cannot answer "what was the configuration of this S3 bucket at 14:32 UTC on the day of the breach?" Required for compliance audit trails (SOC 2, PCI) and for detecting configuration drift. MEDIUM because it's not exploitable — it's a forensics/compliance gap.

**Compliance — S3 access logging (CIS 2.1.4):** Server access logs record every GET, PUT, DELETE on a bucket. Without them, you cannot audit data exfiltration after the fact. Different from CloudTrail (which records API calls at the control plane level) — S3 access logging captures data-plane access. MEDIUM for same reason as Config: compliance/forensics gap, not directly exploitable.

---

## Section 2: LLM Remediation Engine

### Design Goals

1. **Opt-in only** — zero API calls, zero cost if `--llm` not passed
2. **Cheap** — full scan with 19 findings costs ~$0.01
3. **Cached** — one API call per check type, not per finding instance
4. **Structured output** — JSON fields, not prose, so HTML dashboard can render them cleanly

### Model Selection: `claude-haiku-4-5`

Haiku chosen over Sonnet for three reasons:
- Remediation steps are structured and formulaic — Sonnet's reasoning depth is not needed
- ~10x cheaper per token at this task quality level
- Fast enough (~1s per call) that LLM mode doesn't feel slow

If a future version adds blast radius analysis requiring multi-step reasoning (e.g., IAM privilege escalation chains), that specific call can be promoted to Sonnet while the rest stay on Haiku.

### Prompt Design

```
System: You are a senior cloud security engineer with deep AWS expertise.
Given an AWS security finding, return a JSON remediation playbook with exactly
these four fields:
  - immediate_steps: ordered list of CLI commands or console steps to fix now
  - verification: how to confirm the fix worked (command or console check)
  - long_term_controls: preventive controls to stop recurrence (SCP, Config rule, policy)
  - blast_radius: what an attacker could do if this finding is not fixed

Return only valid JSON. No prose outside the JSON object.

Finding: {finding_json}
```

**Why these four fields:**
- `immediate_steps` — the thing the on-call engineer does right now
- `verification` — closes the loop; most CSPM tools skip this entirely
- `long_term_controls` — the PM/platform engineering angle: prevent, don't just fix
- `blast_radius` — forces the reader to understand *why* this matters before they deprioritize it

### Caching Strategy

Cache key = `finding["check"]`. The playbook for `check_public_s3_bucket` is the same regardless of which specific bucket triggered it. Resource-specific context (bucket name, region) is not passed to the LLM — the playbook is general enough to apply to any instance of the check.

This means 19 unique checks = maximum 19 API calls per scan, regardless of how many resources are affected.

### Output

`playbook` field added to each finding dict:

```json
{
  "check": "public_s3_bucket",
  "severity": "CRITICAL",
  "resource": "s3://my-leaked-bucket",
  "detail": "...",
  "remediation": "...",
  "playbook": {
    "immediate_steps": ["aws s3api put-public-access-block ..."],
    "verification": "aws s3api get-public-access-block --bucket my-leaked-bucket",
    "long_term_controls": ["Enable S3 Block Public Access at account level", "Add Config rule s3-bucket-public-read-prohibited"],
    "blast_radius": "Any unauthenticated user can list and download all bucket contents. No credentials required."
  }
}
```

HTML dashboard renders `playbook` as a collapsible detail row below each finding. JSON report includes it at the top level. Terminal prints it when `--llm` is active.

---

## Section 3: Compliance Scoring

### Framework Selection

**CIS AWS Foundations Benchmark v2:** Already partially referenced in README. Industry standard for AWS security audits. SOC 2 auditors, PCI QSAs, and enterprise procurement teams all reference it. Provides a defensible scope boundary: "we cover the controls auditors actually ask about."

**NIST CSF (Cybersecurity Framework):** Broader than CIS — five functions: Identify, Protect, Detect, Respond, Recover. Wiz, Lacework, and AWS Security Hub all map to NIST in their enterprise reporting. Demonstrates risk management thinking beyond a checklist.

**Excluded frameworks and why:**
- *MITRE ATT&CK:* Threat modeling framework, not a posture benchmark. Useful for detection engineering, wrong lens for misconfiguration scanning.
- *ISO 27001:* Organizational controls, not AWS-specific technical controls. Adds complexity without check-level mappability.
- *SOC 2:* Auditor framework, not a technical controls list. Compliance score maps naturally to SOC 2 Trust Services Criteria but we express it in CIS/NIST terms.

### Scoring Logic

**CIS score is the primary scored metric.** Each check = one CIS control. A control **passes** if it produces zero findings. Score = passing controls / total controls × 100.

This is intentionally simple. Weighted scoring (where CRITICAL failures count more) would be more accurate but harder to explain to a non-technical stakeholder. The goal of the score is communication, not precision — that's a deliberate PM decision.

**NIST CSF is informational only — not scored.** NIST checks overlap across functions (e.g., CloudTrail serves both Detect and Respond). Scoring overlapping categories produces double-counting artifacts that mislead more than they inform. Instead, NIST is presented as a category view: "which function does each passing/failing check serve?" This is how Wiz and AWS Security Hub handle NIST mapping in practice.

### NIST CSF Mapping (Primary Assignment)

Each check has one primary CSF function. Checks that serve multiple functions are assigned to the most operationally relevant one.

| CSF Function | CloudWatchdog Checks |
|---|---|
| **Identify** | AWS Config, VPC flow logs, S3 access logging |
| **Protect** | IAM admin policy, IAM wildcard trust, root access key, root MFA, IAM MFA, IAM password policy, unused access keys, EBS encryption, S3 encryption, open SSH/RDP, all-traffic SG, public EC2 |
| **Detect** | GuardDuty, CloudTrail, CloudTrail log validation, public S3, public RDS |
| **Respond** | (served by LLM playbooks — not a posture check) |
| **Recover** | (out of scope for v1) |

### Terminal Output

```
─────────────────────────────────────────────
COMPLIANCE SCORE
─────────────────────────────────────────────
CIS AWS Foundations Benchmark v2
  14 / 19 controls passing  (74%)
  ████████████████░░░░░░░░ 74%

NIST CSF Coverage (informational)
  Identify:  2/3 passing
  Protect:   9/12 passing
  Detect:    3/5 passing
  Respond:   covered by LLM playbooks
  Recover:   out of scope
─────────────────────────────────────────────
```

### JSON Output

```json
{
  "scan_time": "...",
  "region": "us-east-1",
  "compliance_scores": {
    "cis_aws_v2": { "passing": 14, "total": 19, "score_pct": 74 },
    "nist_csf_coverage": {
      "identify":  { "passing": 2, "total": 3 },
      "protect":   { "passing": 9, "total": 12 },
      "detect":    { "passing": 3, "total": 5 },
      "respond":   "covered by LLM playbooks",
      "recover":   null
    }
  },
  "findings": [...]
}
```

### HTML Output

New "Compliance Score" panel above the findings table. Progress bars per framework. Designed to screenshot cleanly for portfolio or Notion page.

---

## Section 4: Documentation Strategy

Three documents serve three audiences.

### `DESIGN.md` (expand existing)

Add three new sections after the existing "What's Next" section:

1. **Why these 8 new checks** — same format as existing tier table
2. **LLM remediation rationale** — opt-in decision, cost model, model selection, prompt design, caching
3. **Compliance framework selection** — CIS + NIST choice, what was excluded and why

### `docs/SECURITY_DOMAINS.md` (new)

Maps every check to:
- Security+ SY0-701 exam objective
- CIS AWS Foundations Benchmark control
- Real-world breach or incident that motivates the check

Designed for use in interviews: "here's how every check in this tool maps to security fundamentals I understand."

### `docs/PRODUCT_DECISIONS.md` (new)

PM decision log format. Each major architectural and product decision:
- Context (what was the situation)
- Options considered
- Decision made
- Rationale

Covers: module split, LLM model selection, caching strategy, opt-in vs. default LLM, CIS vs. NIST vs. MITRE, severity framework, check selection methodology.

Wiz PMs write docs like this internally. Walking in with one is a signal.

### `README.md` (update)

- New checks table (19 total)
- Compliance score sample output
- `--llm` usage and cost note
- ASCII architecture diagram

---

## What's Out of Scope

- Multi-region scan (P1 on roadmap — separate implementation)
- Scheduled scans / diffs (P2 on roadmap)
- Auto-remediation (explicitly excluded from v2 non-goals in DESIGN.md)
- MITRE ATT&CK mapping
- Lambda/EventBridge infrastructure
- Custom rule builder

---

## Success Criteria

1. `python scanner.py --llm` runs end-to-end and produces a playbook for each finding
2. Compliance scores appear in terminal, JSON, and HTML output
3. All 19 checks documented with Security+ objective + CIS control in `docs/SECURITY_DOMAINS.md`
4. `docs/PRODUCT_DECISIONS.md` covers every major design decision with context + rationale
5. An interviewer at Wiz can read `DESIGN.md` and `docs/PRODUCT_DECISIONS.md` and understand both what the tool does and why every decision was made
