# CloudWatchdog — Security+ Domain Coverage Map

Maps every check to a Security+ SY0-701 exam objective, CIS AWS Foundations Benchmark v2 control,
and the real-world incident or breach pattern that motivates the check.

Use this document to walk through the security thinking behind the tool in interviews or portfolio reviews.

---

## Domain A — Identity and Access Management (Security+ Obj 3.7)

### public_s3_bucket — CRITICAL
- **CIS:** 2.1.5
- **Breach pattern:** Capital One 2019 (SSRF → misconfigured S3), Twitch 2021 (overly permissive S3). Public S3 is the most frequently cited cloud data exposure vector.
- **Why CRITICAL:** No credentials required. Data is exposed the moment the ACL is set.

### root_access_key_active — CRITICAL
- **CIS:** 1.4
- **Breach pattern:** Root key compromise = full account takeover, no restrictions. AWS explicitly states root keys should never exist. Common in accounts set up by solo developers.
- **Why CRITICAL:** Root has no permission boundaries. If the key leaks, the account is owned.

### iam_wildcard_trust_policy — CRITICAL
- **CIS:** 1.16
- **Breach pattern:** Overpermissive cross-account trust. An attacker with any AWS account can call sts:AssumeRole if Principal is `*` with no conditions.
- **Why CRITICAL:** No attacker prep required beyond having an AWS account.

### root_mfa_not_enabled — HIGH
- **CIS:** 1.5
- **Breach pattern:** Phished root credentials. Root console login without MFA = game over.
- **Why HIGH:** Requires phishing or credential theft first (one step).

### iam_user_mfa_not_enabled — HIGH
- **CIS:** 1.10
- **Breach pattern:** Credential stuffing against IAM console users. Common in organizations where developers use personal IAM users.
- **Why HIGH:** Credential theft is the first step; MFA blocks escalation.

### iam_admin_policy_on_user — HIGH
- **CIS:** 1.16
- **Breach pattern:** Over-permissioned developer accounts. If a developer's access key leaks, AdministratorAccess on their user = full account compromise.
- **Why HIGH:** Requires key theft first. But blast radius is maximum.

### unused_iam_access_key — HIGH
- **CIS:** 1.12
- **Breach pattern:** Stale credentials in leaked config files, CI/CD logs, or old repos. Keys active for 90+ days with no use are forgotten and thus never monitored.
- **Why HIGH:** If stolen, they go undetected indefinitely (no baseline activity to alert on).

### iam_password_policy_missing / iam_password_policy_weak — MEDIUM
- **CIS:** 1.8–1.9
- **Breach pattern:** Weak passwords + credential stuffing. Common in orgs that rely on IAM users for human access.
- **Why MEDIUM:** Requires password guessing/stuffing; no direct exploit today.

### unencrypted_ebs_volume — MEDIUM
- **CIS:** 2.2.1
- **Breach pattern:** Physical/hypervisor-level access at AWS (extremely unlikely) or snapshot leaks. Relevant for compliance (SOC 2, HIPAA, PCI).
- **Why MEDIUM:** Requires infrastructure-level access to exploit; compliance gap today.

---

## Domain B — Network Security (Security+ Obj 3.3)

### sg_all_traffic_open — CRITICAL
- **CIS:** 5.1
- **Breach pattern:** Protocol `-1` + `0.0.0.0/0` exposes every port. Often created as "temporary" rules during development. Wiz 2024 State of Cloud Security: #1 finding in enterprise scans.
- **Why CRITICAL:** No attacker prep needed. Every port is open.

### open_ssh_rdp_to_world — HIGH
- **CIS:** 5.2, 5.3
- **Breach pattern:** Brute force SSH, credential stuffing RDP. Most common direct attack vector against compute.
- **Why HIGH:** Requires brute force or stolen credentials first (one step).

### public_rds_instance — CRITICAL
- **CIS:** 2.3.2 (equiv.)
- **Breach pattern:** Database port directly exposed. No network boundary between attacker and data.
- **Why CRITICAL:** Direct path to data exfiltration if any DB credential is weak or reused.

### public_ec2_in_public_subnet — MEDIUM
- **CIS:** 5.6
- **Breach pattern:** Compound risk — EC2 in public subnet with public IP + open SG = fully exposed instance. Neither condition is CRITICAL alone; together they are.
- **Why MEDIUM:** The IP alone doesn't mean exploitation; requires weak/open security group as well.

---

## Domain C — Incident Response and Forensics (Security+ Obj 4.3)

### cloudtrail_not_enabled — MEDIUM
- **CIS:** 3.1
- **Breach pattern:** No audit log of API calls. You cannot perform forensics on an incident you can't see.
- **Why MEDIUM:** Doesn't cause a breach, but prevents detecting one.

### cloudtrail_log_validation_disabled — HIGH
- **CIS:** 3.2
- **Breach pattern:** Post-breach log tampering. An attacker with S3 write access can delete trail logs to erase evidence. Log file validation creates a cryptographic chain that detects tampering.
- **Why HIGH:** One step from exploitation: attacker needs S3 write access (already a HIGH finding if present).

### guardduty_not_enabled — HIGH
- **CIS:** (no direct CIS control — GuardDuty is AWS-native)
- **Breach pattern:** Undetected cryptomining, exfiltration, C2 traffic. GuardDuty watches CloudTrail, VPC flow logs, and DNS for anomalous patterns in real time.
- **Why HIGH:** Without it, you're reactive not proactive. Every incident starts later.

---

## Domain D — Risk Management and Compliance (Security+ Obj 5.1)

### config_not_enabled — MEDIUM
- **CIS:** 3.5
- **Breach pattern:** Missing configuration history. Cannot answer "what was the state of this resource at the time of the breach?" Required for SOC 2 Type II and PCI DSS audits.
- **Why MEDIUM:** Not exploitable directly; forensics and compliance gap.

### vpc_flow_logs_disabled — MEDIUM
- **CIS:** 3.9
- **Breach pattern:** No network telemetry. Cannot detect anomalous traffic patterns, lateral movement, or data exfiltration via network analysis.
- **Why MEDIUM:** Reduces detection capability; not directly exploitable.

### s3_access_logging_disabled — MEDIUM
- **CIS:** 2.1.4
- **Breach pattern:** Undetected data exfiltration. CloudTrail records API calls (control plane); S3 access logging records individual object reads (data plane). Both are needed for full forensics.
- **Why MEDIUM:** Compliance and forensics gap. Not directly exploitable.

### s3_encryption_not_enabled — MEDIUM
- **CIS:** 2.1.1
- **Breach pattern:** Data at rest unprotected if bucket or AWS infrastructure is compromised. Required for HIPAA, PCI, SOC 2.
- **Why MEDIUM:** Exploitation requires infrastructure-level access; compliance gap today.
