# CloudWatchdog — Product Decision Log

PM artifact documenting major design decisions: the context, options considered,
choice made, and the reasoning behind it.

This document is designed to be read in a product or engineering interview.
Each entry answers: "Why did you build it this way?"

---

## Decision 1: Module split (monolith → 4 focused modules)

**Context:** Original `scanner.py` contained detection logic, output rendering, and orchestration in one file. As the check count grew from 11 to 19 and two new capabilities (LLM, compliance) were added, the file would have exceeded 800 lines with multiple distinct responsibilities.

**Options considered:**
1. Keep monolith, add features inline
2. Split by capability (checks.py, compliance.py, llm_remediation.py, reporter.py)
3. Package structure with `__init__.py` and subdirectories

**Decision:** Option 2 — flat module split.

**Rationale:** Option 1 produces an untestable, unmaintainable file. Option 3 adds import complexity with no benefit for a 5-file project. Option 2 gives each file one responsibility, makes each testable in isolation, and keeps the import graph flat. A reviewer can read any single file and understand its purpose without context from the others.

---

## Decision 2: LLM opt-in via --llm flag, not default

**Context:** LLM remediation playbooks are the P0 differentiator. Could have made them default behavior.

**Options considered:**
1. Default on (LLM always runs, fails gracefully if no API key)
2. Opt-in via `--llm` flag + env var
3. Separate command (`python remediate.py`)

**Decision:** Option 2 — opt-in.

**Rationale:** Most runs are CI/CD or ad-hoc ops scans where adding $0.01/scan cost and ~20 seconds of latency is unwanted. Making it default degrades the core use case. Option 3 fragments the UX — users would have to run two commands for one workflow. Opt-in preserves zero-cost operation for all users while making the feature discoverable via `--help`.

---

## Decision 3: Claude Haiku over Sonnet for playbook generation

**Context:** Anthropic offers multiple model tiers. Sonnet is more capable but ~10x more expensive.

**Options considered:**
1. claude-sonnet-4-6: higher reasoning, more expensive
2. claude-haiku-4-5-20251001: fast, cheap, sufficient for structured output

**Decision:** Haiku.

**Rationale:** Remediation playbook fields (immediate_steps, verification, long_term_controls, blast_radius) are structured and formulaic. The task is "fill four JSON fields given a well-defined finding schema" — not multi-step reasoning, not novel synthesis. Haiku's output quality is indistinguishable from Sonnet for this specific task at ~10x lower cost. If future versions add IAM privilege escalation chain analysis (multi-hop reasoning), that specific step can be promoted to Sonnet selectively.

---

## Decision 4: Cache LLM playbooks by check name, not resource

**Context:** An account with 40 unencrypted EBS volumes would generate 40 identical API calls without caching.

**Options considered:**
1. No caching — fresh call per finding
2. Cache by check name — one call per unique check type
3. Cache by (check_name, severity) — slightly more granular
4. Pre-generate all 19 playbooks upfront, regardless of findings

**Decision:** Option 2 — cache by check name.

**Rationale:** Option 1 is expensive and slow at scale. Option 3 adds no value — severity doesn't change the remediation steps. Option 4 wastes money generating playbooks for checks that pass. Option 2 is the minimum cache key that eliminates redundancy: the playbook for `public_s3_bucket` is correct for any bucket that triggers it, regardless of bucket name. Resource-specific context (bucket name, region) would marginally improve specificity at the cost of making caching impossible.

---

## Decision 5: CIS scored, NIST informational (not scored)

**Context:** Two compliance frameworks are surfaced. Scoring both seemed natural.

**Options considered:**
1. Score both CIS and NIST CSF independently
2. Score CIS only; NIST as informational category view
3. Score NIST only (broader framework, better for enterprise)

**Decision:** Option 2 — CIS scored, NIST informational.

**Rationale:** NIST CSF checks overlap across functions. `cloudtrail_not_enabled` serves both Detect (you can't see events) and Respond (you can't investigate events). Scoring overlapping categories produces double-counting: a single check's failure reduces your score in two functions simultaneously, which overstates the problem. CIS controls map 1:1 to checks — no overlap, clean math. NIST's value is the function-level category view, not a score. This is how AWS Security Hub handles NIST mapping in practice.

---

## Decision 6: Simple scoring (not weighted by severity)

**Context:** CRITICAL findings have more blast radius than MEDIUM findings. Weighted scoring would reflect that.

**Options considered:**
1. Weighted: CRITICAL failure counts as -4, HIGH as -3, MEDIUM as -2, LOW as -1
2. Simple: each check is pass/fail, score = passing / total

**Decision:** Option 2 — simple scoring.

**Rationale:** The compliance score is a stakeholder communication tool, not a precision risk metric. A VP of Engineering looking at "74% CIS compliant" has a clear, intuitive frame. "Weighted score 61.2 out of 100" requires explanation of the weighting model, which shifts the conversation from "what do we need to fix" to "how does the score work." Simplicity serves communication. Severity is already surfaced via the findings sort order and severity badges — it doesn't need to be in the score too.

---

## Decision 7: Check selection methodology

**Context:** Hundreds of AWS misconfigurations exist. How to choose 19?

**Framework:** Two filters applied to every candidate check:
1. **Frequency in real breaches** — does this appear in breach post-mortems (Capital One, Twitch, CodeSpaces, etc.)?
2. **Time-to-exploit** — how many attacker steps separate this finding from data exposure or account takeover?

CRITICAL = zero steps. HIGH = one step. MEDIUM = compliance/forensics gap, no current exploit path. LOW = hardening.

**What was excluded and why:**
- Lambda misconfigs: API complexity high, breach frequency lower
- IAM privilege escalation chains: requires graph analysis across policies (future v3 feature)
- Container scanning: different surface area, separate tool category
- Multi-cloud: dilutes AWS depth, wrong v1 scope
- Custom rule builder: wrong user — this is for teams without a dedicated detection engineer

The "scan in 30 seconds, understand in 30 seconds" UX goal was the ultimate scope boundary. Every check that didn't pass that test was deferred.
