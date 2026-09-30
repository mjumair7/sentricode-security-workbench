# Implemented scope and limits

The original design describes a large DevSecOps platform. This repository delivers a usable personal security workbench around that design. The distinctions below are deliberate: an adapter in the code is not evidence that every upstream scanner was installed, run, or independently benchmarked.

## Current application

| Area | Available now | Boundary |
|---|---|---|
| Dashboard | Real repositories, scan stages/history, findings, evidence, lifecycle, comparison, exports, audit, settings | Single-owner; no fabricated projects or trend numbers |
| Ingestion | Bounded ZIP upload; public/private GitHub archive imports; branch/tag/commit ref | github.com only; no arbitrary URL fetch, SSH clone, submodules, or local-path API |
| Persistence/jobs | SQLite default; SQLAlchemy PostgreSQL connection option; persisted jobs; atomic claim, lease and heartbeat; embedded or separate worker | One worker recommended; PostgreSQL and multi-process deployment need environment-specific verification |
| Authentication | Owner token, signed sessions, optional GitHub OAuth restricted to a configured owner | No organizations, invitation flow, roles, SAML, or GitHub App installations |
| Lifecycle | Open, confirmed, in progress, resolved, accepted risk, false positive; dismissal reasons; status carry-forward | No automatic proof of a fix; fingerprints can change with evidence or file renames |
| Comparisons | New/resolved/unchanged finding fingerprints between scan reports | No semantic code diff, changed-files-only scan, or Git blame tracking |
| Policies | Dashboard policy snapshot evaluated at scan completion; CLI severity/secret/high-count gates; incomplete enabled-engine coverage fails the web gate | CI consumes explicit CLI flags/policy files; it does not fetch the dashboard's saved policy automatically |
| Exports | JSON, CSV, SARIF 2.1.0, CycloneDX 1.5 SBOM | No PDF report generator |
| AI | Optional selected-finding explanation/remediation/test suggestions; audiences; consent; redaction; local fallback | No automatic triage, calibrated validation confidence, patch application, test execution, or autofix PR |
| Deployment | Static Next.js frontend + FastAPI container; persistent volume; optional Caddy HTTPS and separate worker | No AWS/Terraform production environment, CDN, RDS provisioning, S3, or autoscaling |
| CI | Python tests, TypeScript check/build, Docker build, reusable baseline scan, SARIF artifacts/optional upload | GitHub code-scanning availability depends on repository settings/plan |

## Built-in analysis

| Input | What is checked | Important limits |
|---|---|---|
| Python | AST-based checks for unsafe calls/patterns, selected dynamic SQL/command construction, insecure settings, sensitive logging, limited local assignment traces | Not a whole-program type system or interprocedural taint engine; parse failures are reported |
| JavaScript/TypeScript | Focused lexical checks for dangerous APIs, injection-shaped construction, selected insecure settings and logging | Not a TypeScript compiler analysis; lexical checks can match comments/strings and miss indirect flows |
| Other text languages | Credential patterns and sensitive credential assignments | Java, Go, C/C++, C#, Rust, and SQL do not have a complete built-in SAST engine |
| Secrets | Credential-shaped literals, selected provider formats, private keys, token strings, connection strings, assignment context | No live credential validation; custom/encoded formats may be missed; not a general entropy classifier |
| Confidentiality/DataGuard | Sensitive names reaching selected logging patterns; secret handling | Not comprehensive PII discovery, legal/compliance assessment, or complete data lineage |
| IaC/configuration | Focused Dockerfile, YAML/Kubernetes/Compose/GitHub Actions, Terraform/HCL patterns | Not full schema-aware infrastructure policy evaluation |
| Dependencies | Parses common manifests and lockfiles without installing them | Version constraints stay unresolved unless an exact version is known; no package-manager resolution |

Dependency parsers cover `package.json`, npm lockfiles, pnpm lockfiles, common Yarn lockfile forms, requirements/constraints `.txt` files, `pyproject.toml`, Poetry/uv locks, `go.mod`/`go.sum`, `Cargo.lock`, Maven `pom.xml`, and NuGet `packages.lock.json`. They do not execute Gradle, Maven, npm, pip, or project configuration. Dynamic versions, Maven properties, Gradle files, workspaces, unusual lockfile variants, and complete transitive dependency edges are not fully resolved. The SBOM is an inventory, not a verified build artifact or complete dependency graph.

**Quick** runs current-source and secret checks. **Standard** adds configuration and dependency inventory, plus network intelligence if explicitly enabled. **Deep** runs the standard pipeline and any requested optional tools; it does not silently add full taint analysis, AI review, Git history, or image scanning.

Scans intentionally skip generated/vendor/VCS directories, symlinks, binaries, and files beyond the reading budgets. Check `warnings` and every engine's `completed`, `skipped`, or `failed` status before interpreting results. The scanner supports `.sentricodeignore` patterns for personal use; treat exclusions as part of the reviewed scan policy. The reusable CI workflow passes `--no-project-ignore` so a pull request cannot suppress checks by changing that file.

## Optional intelligence

- **OSV:** queries exact package versions and includes matching advisory evidence and fixed versions when supplied. It caps work at 1,000 packages and 200 advisory-detail fetches; unresolved versions, pagination, caps, and failures can leave partial coverage.
- **CVSS:** reads/calculates available CVSS v3.0/v3.1 base vectors. Unsupported vectors and missing values remain unknown. An unrated advisory gets a clearly identified medium review priority, not an invented CVSS score.
- **EPSS and CISA KEV:** enrich CVE-bearing dependency findings using public data. Missing/failed lookups stay unknown. The result is a snapshot, not a continuously refreshed threat feed.
- **CWE/OWASP:** rules include mappings where known. Not every external or dependency finding has every field, and CVE IDs are only attached where an advisory supplies one.
- **SentriScore:** a documented prioritization heuristic. It does not claim to predict compromise, prove internet exposure, or measure reachability. See [the exact scoring description](architecture.md#scores-and-uncertainty).

## Optional scanner adapters

| Adapter | Implemented command/use | What is not implied |
|---|---|---|
| Semgrep | Fixed bundled rules for Python/JS/TS `eval` and Python pickle deserialization | No complete community ruleset or all-language rule pack is included |
| Bandit | Recursive Python scan; normalized findings | Requires a compatible installed binary or pinned image |
| Gitleaks | Directory scan; optional `--history` for a local Git checkout | ZIP/GitHub archive imports do not contain Git history |
| Checkov | Offline directory/configuration checks with external module downloads disabled | No automatic cloud access or download of Terraform modules |
| Trivy | Offline **configuration** scanning | No container-image, operating-system CVE, or vulnerability-database image scan |
| Syft | Directory inventory exported as CycloneDX | No build execution or complete proof of the shipped artifact's contents |

These tools are not installed in the web image. CLI container mode requires pre-pulled images and `SENTRICODE_<TOOL>_IMAGE` values pinned with `@sha256:...`. Installed-tool mode requires deliberate `--local-tools` use. Unavailable optional tools are reported as skipped. Use `--require-engines Bandit,Gitleaks` to make missing/skipped required tools fail the CLI with exit code 2. Real upstream scanner compatibility and container execution must be verified on the machine where you enable them.

The dependency intelligence client talks directly to OSV. There is no separate `osv-scanner`, `npm audit`, `pip-audit`, or OWASP Dependency-Check adapter in this release.

## Deferred from the larger design

Organizations/RBAC; GitHub App installation/webhooks; scheduled scans; Redis/Celery; S3/MinIO artifacts; Alembic migrations; full cross-file/source-to-sink analysis; attack-path proof; complete dependency graphs; image CVE scanning; PDF exports; validated autofix patches/PRs; cloud infrastructure provisioning; per-tenant scanner isolation; production abuse controls; immutable audit logging; measured precision/recall benchmarks; and a maintained public evaluation corpus are future work.

The included regression tests check defined cases. They are not a measured accuracy benchmark against a representative vulnerability dataset. No performance, recall, or precision numbers are claimed.
