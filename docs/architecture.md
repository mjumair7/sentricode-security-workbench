# Architecture

SentriCode has one Python package and one web client. The production frontend is a static Next.js export served by FastAPI, so a deployment needs one application image rather than a separate Node.js server. SQLite is the default database; SQLAlchemy can also connect to PostgreSQL.

```text
Browser / CLI
      |
      +-- CLI --> scanner --> JSON / CSV / SARIF / CycloneDX
      |
      +-- FastAPI --> bounded ZIP / GitHub ingestion
                        |
                        v
                   database job record
                        |
                 embedded or separate worker
                        |
                        v
                repository profiler
                        |
                secrets + source checks
                        |
                config + dependency inventory
                        |
                optional network enrichment
                        |
                normalized report + findings
                        |
                database + dashboard
```

The CLI additionally exposes optional external scanner adapters. The hosted API deliberately does not expose host paths, installed-tool execution, or a Docker socket.

## Scan lifecycle

An upload is checked for size and extracted into a private job directory. GitHub imports accept a strict `https://github.com/owner/repository` URL plus a branch, tag, or commit. Downloads follow only the expected GitHub archive redirect, and the GitHub token is not forwarded to another host.

The API records a queued job and returns immediately. A worker claims it with a conditional database update, sends heartbeats, and updates the visible stage. A lease prevents an old worker from overwriting a job claimed by a new one. Jobs with stale heartbeats can be retried. Source is removed after a completed or failed job; reports remain until deleted. A crash can leave temporary files until recovery or periodic orphan cleanup, so the data volume is still sensitive.

The workspace policy is captured when a web scan is queued, then evaluated against the completed report. Its result records violations and coverage completeness. Editing the workspace policy does not rewrite old scans' results. The CLI has its own explicit policy flags/files for local and CI use.

The default is one embedded worker and one API process. `compose.worker.yaml` separates them while retaining a shared jobs volume. There is no Redis, Celery, S3, distributed scheduler, or database migration framework in this release. PostgreSQL support does not by itself make the service horizontally scalable.

## Finding records

All engines produce the same basic shape: rule, scanner, category, severity, file/line, redacted evidence, remediation, references, confidence, and optional standards/intelligence fields. A fingerprint combines rule ID, relative file path, and normalized evidence, keeping a finding stable when blank lines are inserted. Identical repeated expressions get occurrence identifiers.

The web database gives each finding instance a separate ID. Status and review reasons carry forward to matching findings for the same repository. Scan comparisons are fingerprint comparisons; they are not a Git semantic diff or proof that a vulnerability was fixed. Renames or changed evidence can look like one resolved and one new finding. Upload names identify local projects, so use a consistent name for repeated scans of the same project and different names for unrelated projects.

## Scores and uncertainty

`SentriScore` is a sorting heuristic. Base severity weights are 92/75/50/25/5 for critical through informational, multiplied by `0.8 + 0.2 × confidence`. Available EPSS adds up to 8 points, confirmed KEV membership adds 12, and the result is capped at 100. Confidence is an author-assigned rule heuristic, not a calibrated probability.

The scan posture score starts at 100 and subtracts 18/9/3/1/0 per finding by severity, stopping at zero. It summarizes the findings reported in that scan; it does not measure coverage or predict compromise. Missing CVSS, EPSS, and KEV values stay unknown. A skipped engine is never reported as having found zero vulnerabilities successfully.

## AI boundary

The AI action is separate from scanning. It sends one finding's limited redacted context only after consent. It supplies no command, browser, filesystem, or repository-write tools to the model. Source comments are untrusted input. Suggestions do not change findings, apply a patch, run tests, create a commit, or open a pull request. Local rule guidance is available without provider credentials.

## Places to extend

- Add rules and regression fixtures under the existing analysis modules before adding more UI metrics.
- Add parsers for missing lockfile formats without running package managers inside scanned projects.
- Introduce migrations before changing the persistent schema for an installed deployment.
- Put job source and artifact handling behind a storage interface before adding multiple machines.
- Add real identity, authorization, quotas, isolation, and operational controls before accepting unrelated users' private repositories.

The application is arranged around these boundaries so those additions do not require pretending the personal deployment already has them.
