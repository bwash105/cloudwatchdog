# CloudWatchdog — Product Design

**Author:** Brian L. E. Washington  
**Purpose:** Document the PM decisions behind CloudWatchdog — not just what it detects, but why.

---

## Problem

Security teams drown in alerts. CSPM tools often fail on three axes:

1. **Noise** — hundreds of findings with no clear priority
2. **Context gap** — what's wrong, but not what to do about it
3. **Trust gap** — severity labels that feel arbitrary, not grounded in real risk

CloudWatchdog is a deliberately scoped v1 that optimizes for *actionable signal*, not coverage breadth.

---

## Why These 11 Checks

Each check was chosen against two filters: **frequency in real breaches** and **time-to-exploit**.

| Tier | Checks | Rationale |
|------|--------|-----------|
| **Ship first (v0)** | Public S3, root access key, open SSH/RDP, root MFA, unencrypted EBS, CloudTrail | Public S3 and root keys appear in the majority of high-profile cloud incidents (Capital One, Twitch). Open SGs are the most common direct attack vector. CloudTrail and EBS encryption are compliance blockers (SOC 2, PCI). |
| **Ship next (v1)** | Public RDS, unused access keys, IAM password policy, S3 encryption, VPC flow logs | RDS public exposure is CRITICAL but less common than S3 — same blast radius, lower base rate. Unused keys and weak password policies are credential-theft precursors. S3 encryption and flow logs are compliance gaps with no immediate exploit path — important for enterprise buyers, lower urgency for startups. |

**What I deliberately excluded from v1:** Lambda misconfigs, IAM privilege escalation chains, container scanning, multi-cloud. Each adds API complexity and dilutes the "scan in 30 seconds, understand in 30 seconds" UX goal.

**CIS alignment:** Checks map to CIS AWS Foundations Benchmark controls where applicable. CIS gives credibility with security buyers and a defensible scope boundary — "we cover the controls auditors actually ask about."

---

## Severity Framework

Severity is not CVSS copy-paste. It's a **prioritization model for a human operator with limited time**.

| Level | Definition | Product test |
|-------|------------|--------------|
| **CRITICAL** | Exploitable now. No attacker prep. Full account or data exposure. | Would I wake someone at 2am? |
| **HIGH** | One step from exploitation. Well-documented attack paths. | Would I block a deploy? |
| **MEDIUM** | No direct exploit today. Compliance or forensics gap. | Would an auditor flag it? |
| **LOW** | Defense-in-depth hardening. | Would I put it in a backlog grooming session? |

**Example decisions:**

- **Public S3 → CRITICAL.** Data is exposed. No credentials needed.
- **Open SSH → HIGH, not CRITICAL.** Requires brute force or stolen keys — one step away.
- **Unencrypted EBS → MEDIUM, not HIGH.** Requires hypervisor-level access. Real for compliance, not for incident response tonight.
- **CloudTrail disabled → MEDIUM.** You're blind during an incident, but nothing is actively leaking.

This framework drives sort order in the report: CRITICAL findings always surface first, regardless of scan order.

---

## Output Design

Three output formats, one schema:

1. **Terminal** — for engineers running ad-hoc scans
2. **JSON** — for CI/CD, Slack, ticketing integrations
3. **HTML dashboard** — for stakeholders who won't read a CLI

Every finding includes a **remediation string**. This is intentional: the #1 CSPM UX complaint is "now what?" Static remediation covers 80% of cases at zero cost. LLM-assisted playbooks (roadmap) handle the remaining 20% — environment-specific steps, blast radius analysis, rollback plans.

---

## What's Next and Why

| Priority | Feature | Why |
|----------|---------|-----|
| **P0** | LLM remediation playbooks | Differentiator. Turns CloudWatchdog from a scanner into a workflow tool. Opt-in via API key — no cost for users who don't need it. |
| **P1** | Multi-region scan | Single-region scan misses RDS/SG findings in other regions. Required before calling this production-ready. |
| **P2** | Scheduled scans + diff | "What changed since yesterday" is the daily-use case for platform teams. Findings without delta are a one-time audit tool. |
| **P3** | AWS Organizations support | Enterprise expansion. Same checks, aggregated across accounts, with account-level roll-up in the HTML dashboard. |

**Non-goals for v2:** Auto-remediation (too much trust required), multi-cloud (dilutes AWS depth), custom rule builder (wrong user — this is for teams without a dedicated detection engineer).

---

## How to Read This Repo

- `scanner.py` — detection logic and report generation
- `DESIGN.md` — this document (the PM artifact)
- `README.md` — user-facing docs and quick start

The code proves feasibility. The design doc proves product thinking.
