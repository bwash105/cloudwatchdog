# CloudWatchdog — AWS Cloud Security Posture Monitor

Open-source CSPM tool built as a PM portfolio artifact. Scans AWS environments for common misconfigurations, implements a severity classification framework, and generates prioritized risk reports.

**Built by:** Brian L. E. Washington  
**Why:** Demonstrate CSPM product thinking — from detection schema design to severity prioritization to remediation UX.

## What It Detects

| Check | Severity | CIS Benchmark |
|---|---|---|
| Public S3 buckets (ACL or policy) | 🔴 CRITICAL | CIS AWS 2.1.5 |
| Public RDS instances | 🔴 CRITICAL | — |
| Root account access key active | 🔴 CRITICAL | CIS AWS 1.4 |
| Security groups open SSH/RDP to 0.0.0.0/0 | 🟠 HIGH | CIS AWS 5.2, 5.3 |
| Root account MFA not enabled | 🟠 HIGH | CIS AWS 1.5 |
| IAM users with console password, no MFA | 🟠 HIGH | CIS AWS 1.10 |
| Unused IAM access keys (>90 days) | 🟠 HIGH | CIS AWS 1.12 |
| Unencrypted EBS volumes | 🟡 MEDIUM | CIS AWS 2.2.1 |
| IAM password policy gaps | 🟡 MEDIUM | CIS AWS 1.8–1.9 |
| S3 default encryption not enabled | 🟡 MEDIUM | CIS AWS 2.1.1 |
| VPC flow logs not enabled | 🟡 MEDIUM | CIS AWS 3.9 |
| CloudTrail not enabled | 🟡 MEDIUM | CIS AWS 3.1 |

## Severity Framework

Designed as a PM product decision — not arbitrary:

- **CRITICAL** — Exploitable now with no attacker preparation. Full account or data exposure risk.
- **HIGH** — One step from exploitation. Common, well-documented attack paths exist.
- **MEDIUM** — Increases attack surface but no direct exploit path today. Required for compliance (SOC 2, PCI, HIPAA).
- **LOW** — Hardening gap. Minimal immediate risk but reduces defense-in-depth.

## Usage

```bash
pip install boto3
python scanner.py                        # default AWS profile, us-east-1
python scanner.py my-profile us-west-2  # named profile + region
```

Outputs:
- Terminal report (color-coded by severity, with remediation)
- `cloudwatchdog-report.json` for downstream integration
- `cloudwatchdog-report.html` dashboard (use `--html custom.html` for a custom path)

## Product Design Notes

The detection schema is a PM artifact. Key product decisions made:

1. **Scope**: AWS only (v1). Why: largest market share, richest API surface, most documented misconfigs.
2. **11 checks**: prioritized by CVSS severity + frequency in real-world breaches. Public S3 + root key = responsible for majority of high-profile cloud incidents.
3. **Remediation-first output**: every finding includes a concrete remediation step. Most CSPM tools show you what's wrong without telling you what to do — this is the UX gap.
4. **JSON output**: enables integration into CI/CD, Slack alerts, ticketing systems.

## Roadmap

- [x] IAM password policy enforcement (CIS 1.8–1.11)
- [x] Public RDS instance detection
- [x] Unused IAM access keys (>90 days)
- [x] VPC flow logs not enabled
- [x] S3 server-side encryption not enabled
- [ ] LLM-assisted remediation playbooks (Anthropic API)
- [x] HTML dashboard output
