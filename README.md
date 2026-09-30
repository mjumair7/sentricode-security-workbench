# SentriCode

A security workbench for the code I build.

I started this after attending Elevate (Nrth) and sitting through a seminar with a Capital One speaker about AI automated code checks and vulnerability checks. I wanted to understand what goes into that workflow and build something I could keep using on my own projects.

SentriCode brings source checks, secret detection, dependency inventory, confidentiality checks, scan history, and optional AI explanations into one place. It runs locally, has a CLI for any checkout, and can be deployed as a private web application. The connection to the seminar is personal inspiration; this project is not affiliated with Capital One or Elevate.

The part I wanted to get right was the connection between a finding and what to do next: show the evidence, explain the risk, keep track of the decision, and check whether the same issue is still there on the next scan. I use the scanner as another review step, and still read the findings myself.

## Run it

The easiest option is Docker Desktop on a personal computer, or Docker Engine with Compose on Linux.

```sh
./scripts/configure
docker compose up -d --build
```

Save the owner token printed by `scripts/configure`, then open **http://127.0.0.1:8000** and sign in. The first build downloads dependencies and builds the dashboard. Use **New scan** to upload a ZIP of your project or enter a GitHub repository URL. **Try a sample** scans a deliberately vulnerable project; its results are labelled as demo data. For Windows PowerShell, use the [manual configuration steps](docs/deployment.md#windows-powershell).

Your reports live in the `sentricode-data` Docker volume. These are the commands I keep handy:

```sh
docker compose stop             # Pause it, keep the reports
docker compose up -d            # Start it again anytime
docker compose logs -f app      # See what is happening
docker compose up -d --build    # Rebuild after updating the source
```

Docker must be running. `restart: unless-stopped` restarts the service after a host reboot when Docker starts, unless you previously stopped it. Do not use `docker compose down -v` unless you intend to delete saved reports. No chat session, hosted AI service, or API key is needed to keep the app running.

For a source installation on macOS or Linux, install Python 3.11+ (3.12 recommended), Node.js 22 and Corepack, then:

```sh
./scripts/setup
./scripts/start
```

After the first setup, only `./scripts/start` is needed. It loads `.env`, serves the built dashboard, and listens on `127.0.0.1:8000`. Keep that terminal open, or use Docker for a background service. On Windows, use Docker Desktop or run these scripts inside WSL. See [local development](docs/development.md) for separate frontend/backend development.

## Use it on your other projects

The app is not tied to this repository. Upload another project's ZIP, import another GitHub repository, or use the CLI installed by `scripts/setup`:

```sh
# The path can be any checkout you own.
.venv/bin/sentricode scan /path/to/my-project

# Save a complete report or a software bill of materials.
.venv/bin/sentricode scan /path/to/my-project --format json -o reports/report.json
.venv/bin/sentricode scan /path/to/my-project --format sbom -o reports/sbom.json

# Fail a build on findings that cross your policy.
.venv/bin/sentricode scan /path/to/my-project --policy examples/policy.json
```

No dependency installation or application build is performed inside scanned projects. Built-in checks work without external scanners or network access. Coverage varies by language and file type; this is most useful for Python, JavaScript/TypeScript, common dependency manifests, and infrastructure configuration. A clean report is not proof that a project is secure.

## What is here

- A Next.js/React dashboard backed by FastAPI, with real scan progress, findings, scan comparisons, exports, policies, and audit history.
- Local static rules, secret detection with redacted evidence, sensitive logging checks, dependency inventory, and a CycloneDX SBOM.
- Optional scanner integrations and network vulnerability enrichment. Engine status tells you what actually ran, failed, or was skipped.
- Owner-token authentication and optional GitHub OAuth restricted to one configured owner; GitHub repository import is separate from sign-in.
- Optional AI explanations for a selected finding, with explicit consent and limited redacted context. No API key means local guidance remains available.
- A CLI, JSON/CSV/SARIF/SBOM exports, and reusable pull-request checks with a baseline.

This release is a **single-owner workbench**. The larger design includes ideas such as organizations, full interprocedural analysis, image scanning, cloud autoscaling, and reviewed autofix pull requests. Those are not presented as finished features. [Coverage and limitations](docs/coverage.md) maps the implementation to that design, and [security](docs/security.md) explains the trust boundaries.

## Publish it and keep it available

The source can go in a public or private GitHub repository. The running application needs a server for the API, worker, and saved reports; GitHub Pages alone cannot host it.

1. Extract the source ZIP and publish the extracted folder with GitHub Desktop or Git. Keep `.env`, reports, and `data/` out of the repository.
2. Run Docker Compose on a Linux server you control.
3. Set a random owner token and your HTTPS address, then start the included Caddy reverse proxy.

The exact commands, domain setup, persistent storage, backups, and GitHub upload steps are in [deployment](docs/deployment.md). [CI integration](docs/ci.md) shows how to reuse the scanner in any of your other repositories.

## Work on the project

```sh
make check   # Python tests and TypeScript checks
make build   # Build and copy the dashboard into the Python app
make start
```

The source is intentionally kept fairly small:

```text
backend/sentricode/   API, worker, ingestion, scanners, CLI, exports
frontend/            Next.js dashboard
tests/               Scanner and API/security regression tests
scripts/             Setup and local launch helpers
deploy/              HTTPS reverse proxy configuration
docs/                Architecture, coverage, deployment, and CI
.github/workflows/   Build/test and reusable security checks
```

Python versions are pinned in `pyproject.toml` and the requirements lock files. The frontend uses `frontend/pnpm-lock.yaml`. [Architecture](docs/architecture.md) describes the design and the places I would change first if the project grows.

MIT licensed. Please report security issues as described in [SECURITY.md](SECURITY.md).

Operational references: [Docker service and restart settings](https://docs.docker.com/reference/compose-file/services/), [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https), and [GitHub's workflow security guidance](https://docs.github.com/en/actions/reference/security/secure-use).
