# CloudWatchdog — AWS Cloud Security Posture Monitor

Open-source CSPM tool built as a PM portfolio artifact. Scans AWS environments for common misconfigurations, implements a severity classification framework, and generates prioritized risk reports.

**Built by:** Brian L. E. Washington  
**Why:** Demonstrate CSPM product thinking — from detection schema design to severity prioritization to remediation UX.

→ **[Product design doc (DESIGN.md)](DESIGN.md)** — why these checks, how severity works, what's next.

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

## Severity Framework

Designed as a PM product decision — not arbitrary:

- **CRITICAL** — Exploitable now with no attacker preparation. Full account or data exposure risk.
- **HIGH** — One step from exploitation. Common, well-documented attack paths exist.
- **MEDIUM** — Increases attack surface but no direct exploit path today. Required for compliance (SOC 2, PCI, HIPAA).
- **LOW** — Hardening gap. Minimal immediate risk but reduces defense-in-depth.

## Usage

```bash
pip install -r requirements.txt
python scanner.py                              # default AWS profile, us-east-1
python scanner.py my-profile us-west-2        # named profile + region
python scanner.py --llm                        # add LLM remediation playbooks (requires ANTHROPIC_API_KEY)
python scanner.py my-profile us-east-1 --llm  # full options
```

**LLM mode cost:** ~$0.01 per full scan (19 unique check types × ~500 tokens × claude-haiku-4-5 pricing). Opt-in only.

## Sample Output

Terminal scan (11 checks, findings sorted by severity):

```
🔍 CloudWatchdog — AWS Security Posture Scan
   Region: us-east-1 | Profile: default

   Running: check_public_s3_buckets... ✅ clean
   Running: check_s3_encryption... ✅ clean
   Running: check_root_access_key... ✅ clean
   Running: check_unused_access_keys... ✅ clean
   Running: check_iam_password_policy... ⚠️  1 findings
   Running: check_open_ssh_rdp... ✅ clean
   Running: check_mfa_root... ✅ clean
   Running: check_public_rds... ✅ clean
   Running: check_unencrypted_ebs... ✅ clean
   Running: check_vpc_flow_logs... ⚠️  1 findings
   Running: check_cloudtrail_disabled... ✅ clean

Findings: 2 total
  🟡 MEDIUM: 2

1. 🟡 [MEDIUM] iam_password_policy_missing
   Resource:     iam::account
   Detail:       No IAM account password policy configured.
   Remediation:  Set a password policy: min length 14, reuse prevention 24...

2. 🟡 [MEDIUM] vpc_flow_logs_disabled
   Resource:     vpc:vpc-04ef9c7e (unnamed)
   Detail:       VPC vpc-04ef9c7e has no active flow logs.
   Remediation:  Enable VPC Flow Logs to CloudWatch Logs or S3 for all VPCs.
```

HTML dashboard (opens in browser after each scan):

![CloudWatchdog security posture report](docs/report-screenshot.png)

## Product Design Notes

The detection schema is a PM artifact. Key product decisions made:

1. **Scope**: AWS only (v1). Why: largest market share, richest API surface, most documented misconfigs.
2. **11 checks**: prioritized by CVSS severity + frequency in real-world breaches. Public S3 + root key = responsible for majority of high-profile cloud incidents.
3. **Remediation-first output**: every finding includes a concrete remediation step. Most CSPM tools show you what's wrong without telling you what to do — this is the UX gap.
4. **JSON output**: enables integration into CI/CD, Slack alerts, ticketing systems.

