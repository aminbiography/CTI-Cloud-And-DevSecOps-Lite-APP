Live URL:   https://aminbiography.github.io/CTI-Cloud-And-DevSecOps-Lite-APP/

---

## Description for users (cloud engineers, DevOps, AppSec)

### What this page is

**Cloud and DevSecOps Lite APP** is a browser-only helper that performs **static, non-invasive security checks** on text you paste into it. It does not deploy anything, scan live targets, or attempt exploitation. The intent is fast, explainable hygiene checks you can run during reviews, PRs, or incident follow-up.

### What it helps you do

The app provides four tools (tabs):

1. **IaC Guardrails (Terraform/Kubernetes)** – flags common insecure infrastructure patterns.
2. **Secrets & Credential Hygiene** – detects likely secrets in code/config/log text using conservative heuristics.
3. **CI/CD Pipeline Risk Checks** – identifies risky pipeline patterns (supply-chain and permissions issues).
4. **IAM Least-Privilege Helper** – reviews IAM policies for broad permissions and suggests safer templates.

All tools show:

* **Findings list** with severity (High/Medium/Low), explanation, and recommended fix.
* **KPIs** (counts by severity).
* Optional **snippets** to see the relevant portion of the pasted text.

---

### Tab 1: IaC Guardrails (Terraform / Kubernetes)

**Input:** Terraform-like HCL or Kubernetes YAML (auto-detect available).
**Controls:**

* Guardrail profile: **Baseline** vs **Strict (prod)**
* Cloud context: Cloud-agnostic / AWS / Azure / GCP (used for advisory nudges)

**Example findings you may see:**

* Terraform: security groups with `0.0.0.0/0`, `publicly_accessible=true` on databases, encryption disabled, missing versioning, wildcard-like policy content.
* Kubernetes: `privileged: true`, `hostNetwork: true`, `allowPrivilegeEscalation: true`, missing non-root settings, missing resource limits, `:latest` image tags.

**How to use it:**

* Paste a module, manifest, or PR diff excerpt.
* Run **Lint** to prioritize high-risk items before merge/deploy.

---

### Tab 2: Secrets & Credential Hygiene

**Input:** Any text (code snippets, CI YAML, .env content, logs).
**Controls:**

* Detection scope: **Balanced / Strict / Minimal** (changes sensitivity)
* Auto-redact output: **Yes** by default (recommended)
* Max findings limit

**What it flags (examples):**

* Private key blocks
* AWS access key IDs
* GitHub tokens
* JWT-like tokens
* Service account key hints and common connection-string markers
* High-entropy strings near secret-like variable names (e.g., `token=...`)

**How to use it:**

* Paste suspicious config/log output from a pipeline or app.
* Run **Scan**, then rotate/remove secrets if exposure is likely.

---

### Tab 3: CI/CD Pipeline Risk Checks

**Input:** GitHub Actions, GitLab CI, Jenkinsfile, or generic YAML (auto-detect available).
**Controls:**

* Risk profile: Baseline vs Strict
* Repo sensitivity: Normal vs High (prod deploy / secrets)

**Key patterns flagged:**

* **Unpinned GitHub Actions** references (using tags/versions instead of commit SHAs)
* **Broad workflow permissions** (e.g., `write-all`, write permissions)
* **Unsafe remote script execution** (`curl | bash`, `wget | sh`)
* **Missing provenance/signing** signals for high-sensitivity repos
* **Potential secret printing** to logs
* Risky GitHub event usage such as `pull_request_target` combined with secrets

**Extra capability:** Export a JSON report (`cicd_risk_report.json`) after running analysis.

---

### Tab 4: IAM Least-Privilege Helper

**Input:** AWS IAM policy JSON (or generic JSON best-effort).
**Controls:**

* Strictness: Baseline vs Strict
* Assumed scope: Application role vs Admin role (still discourages wildcards)

**What it checks:**

* Wildcard permissions in Action or Resource (`*`, `service:*`)
* High-impact services/actions (e.g., broad IAM, KMS decrypt, Secrets Manager access, S3 wildcard, etc.)
* Missing Conditions on Allow statements (especially in strict/app role mode)

**Output includes:**

* Findings list with details and suggested fixes
* A **Suggested rewrite template** to guide scoping actions/resources and adding basic conditions
* Export of review results (`iam_review.json`)

---

## Description for developers (implementation and extension)

### High-level architecture

* Single HTML file with:

  * UI: tabbed layout, two-column grid (input left, results right)
  * Rendering: shared `renderFindings(prefix, findings)` populates KPIs and list items
* No external dependencies; logic is pure client-side JavaScript.
* Design goal: **transparent heuristics** that are easy to modify.

### Shared utility functions

* `setTab(active)` toggles panels using `hidden` class and `aria-selected`.
* `escapeHtml()` prevents HTML injection in rendered findings.
* `badgeClass(sev)` maps severity to CSS style (good/warn/bad).
* `renderFindings(prefix, findings)` updates:

  * `*-last`, `*-count`, severity KPIs, and `*-list`
  * Supports optional fields: `code`, `title`, `detail`, `fix`, `snip`

---

### Module 1: IaC Guardrails

**Auto-detection:** `detectIacKind(raw)`

* Terraform indicators: `resource "..."`, `provider "..."`, `module "..."`
* Kubernetes indicators: `apiVersion:`, `kind:`

**Terraform linting:** `lintTerraform(raw, profile, cloud)`

* Regex-based checks for:

  * Open ingress to `0.0.0.0/0`
  * `publicly_accessible = true`
  * encryption disabled patterns
  * versioning disabled patterns
  * wildcard hints near policy blocks
* Cloud-specific advisory (AWS example: CloudTrail not obvious in snippet)
* Snippets extracted using `extractSnippet(text, re)` (context slice around match)

**Kubernetes linting:** `lintK8s(raw, profile)`

* Regex checks for common Pod/container hardening misses:

  * host networking, privileged containers, privilege escalation
  * missing non-root configuration (absence-based heuristic)
  * missing resource limits (absence-based heuristic)
  * mutable `:latest` image tags

**Developer extension points:**

* Add new rules as discrete regex checks returning `{sev, code, title, detail, fix, snip}`.
* Consider a lightweight YAML parser for real K8s structure (to reduce false positives) and an HCL parser for Terraform if you want correctness over simplicity.

---

### Module 2: Secrets scanning

**Entropy heuristic:** `entropy(str)` (Shannon entropy approximation)
**Redaction:** `redact(val)` shows first 3 and last 3 chars.

**Scanner:** `scanSecrets(raw, scope, doRedact, maxFindings)`

* Line-by-line scanning with two strategies:

  1. Known token/key patterns (private key markers, AWS Access Key ID format, GitHub token format, JWT-like tokens, etc.)
  2. Variable assignment heuristic: key names matching `(api_key|token|secret|password|...)` plus value length + entropy thresholds (tuned by scope)

**Developer notes:**

* This is intentionally “conservative detection,” not validation. Avoid adding any logic that attempts to authenticate or call external APIs.
* For performance, it exits early at `maxFindings`.
* If you accept untrusted regex patterns in the future, add safeguards against catastrophic backtracking.

---

### Module 3: CI/CD risk checks

**Auto-detection:** `detectCiKind(raw)`

* Heuristic hints for GitHub Actions, GitLab, Jenkinsfile, else “generic.”

**Checks:** `ciFindings(raw, kind, profile, repo)`

* GitHub Actions:

  * `uses:` references not pinned to a 40-char SHA are flagged (severity increases in strict/high-sensitivity repos).
  * Broad permissions patterns flagged (`write-all`, `contents: write`).
  * `pull_request_target` + `secrets` flagged as high risk.
* Generic pipeline:

  * `curl|wget | bash|sh` flagged.
  * Potential secret printing (`echo ${{ secrets.* }}` or echoing secret-like variables).
  * Missing provenance/signing signals suggested for “high” repos (heuristic check for cosign/slsa/provenance keywords).

**Export:**

* Stores the most recent findings in `ciCache`.
* Exports JSON via Blob to `cicd_risk_report.json`.

**Developer extension points:**

* Add support for more CI types (Azure DevOps pipelines, CircleCI).
* Add job-level permission modeling (GitHub Actions) instead of simple regex checks.
* Add signature verification recommendations as structured “controls” with maturity levels.

---

### Module 4: IAM least privilege

**Parsing:** `parseJsonSafe(raw)` returns object or null.
**Normalization:** `asArray(x)` ensures `Action`/`Resource`/`Statement` are iterable.

**Review:** `iamReview(policy, profile, scope)`

* Flags:

  * Allow statements with wildcard actions/resources
  * Presence of high-impact action prefixes (heuristic list)
  * Missing `Condition` on Allow statements (especially strict/app scope)
* Produces:

  * `findings[]`
  * `suggest` policy template that “nudges” toward scoping and adding region condition
* Export uses `iamCache` to write `iam_review.json`.

**Developer notes:**

* The suggested rewrite is a template, not a correct policy synthesis. It intentionally avoids inventing ARNs and encourages human review.
* For improved accuracy, consider:

  * parsing AWS IAM condition keys and recommending context-aware conditions (Vpce, tags, MFA, principal ARN),
  * detecting `NotAction` / `NotResource`,
  * distinguishing identity vs resource policies and permissions boundaries.

---

## Positioning and safe-use guidance (applies to all tabs)

* This app is designed for **local static review**. It does not replace policy-as-code engines (OPA/Conftest), IaC scanners (tfsec/checkov), or full secret scanners (gitleaks/trufflehog), but it is useful for quick, portable triage.
* Best practice use: run during PR review, document exceptions, and enforce expiry dates for temporary relaxations.

---
