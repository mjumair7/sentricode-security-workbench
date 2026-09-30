# Local development

Use Python 3.11+ and Node.js 22. Python 3.12 is the version used by the Docker image and CI. Install Corepack if your Node installation does not include it. The frontend pins pnpm in `package.json`.

```sh
./scripts/setup
./scripts/start
```

`scripts/setup` makes `.venv`, installs the version-locked Python dependencies, installs the Python package in editable mode, installs the locked frontend dependencies, builds the dashboard, and copies it into the backend. Existing `.env` settings are preserved. `PYTHON_BIN=/path/to/python3.12 ./scripts/setup` selects a particular interpreter.

For dashboard development, run these in separate terminals:

```sh
# Terminal 1: API and scan worker
./scripts/start --reload

# Terminal 2: Next.js development server
cd frontend
corepack pnpm dev
```

Open http://127.0.0.1:3000 for live frontend updates. The frontend forwards `/api` requests to the backend on port 8000. Local origins are allowed by default. After changing the frontend, use `make build` before viewing the built version on port 8000.

## CLI-only installation

No Node.js installation or frontend build is needed for the CLI:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/sentricode --help
.venv/bin/sentricode scan /path/to/project
```

You can also activate the environment and use `sentricode` directly. The CLI can scan an absolute path anywhere you have read access; it does not require copying your project into this repository. Runtime files, vendored dependencies, and other excluded directories are intentionally skipped; check the scanner's warning and engine output for coverage.

## Tests and builds

```sh
.venv/bin/python -m pytest
.venv/bin/python -m pytest --cov=sentricode --cov-report=term-missing
cd frontend
corepack pnpm typecheck
corepack pnpm build
```

The Python tests exercise the scanners, exports, archive ingestion, and API/security behavior. Scanner fixtures are deliberately unsafe examples and must never be run as applications. Type checking and a production build verify the frontend's build contract; they are not a complete browser accessibility or end-to-end test suite.

The frontend export is copied by `scripts/copy_frontend.py`. Run that before `python -m build` if you want a Python wheel containing the dashboard. A source checkout without a frontend build still supports the CLI and API, but the dashboard needs the static files.

## Dependency updates

`requirements.lock` pins the transitive runtime dependencies. `requirements-dev.lock` adds test/build tools; `requirements-postgres.lock` adds the optional PostgreSQL driver. Top-level package versions are also pinned in `pyproject.toml`. When updating a dependency, update the affected pins together, resolve in a fresh Python 3.12 environment, run the tests, then rebuild the image. These are version locks, not hash-verified offline bundles.

Use `corepack pnpm install --frozen-lockfile` to install the frontend and intentionally regenerate its lock only when changing dependencies. GitHub Actions are pinned to commits. Dependabot is configured to propose updates, which still need review. Container base images use maintained version tags; record image digests in your own release process if you need byte-for-byte image provenance.

## Configuration

`scripts/start` loads the root `.env` as key/value data; variables already in the environment take precedence. Docker Compose loads `.env` through `env_file`. A direct `uvicorn sentricode.api:app` command reads the process environment; it does not load `.env` by itself. Copying a config file does not change a running process, so restart after editing it.

Data defaults to `./data` for local runs. Set `SENTRICODE_DATA_DIR` to choose another directory. Reports and audit records are sensitive and should remain out of Git. See [security](security.md) and [deployment](deployment.md) before binding the API outside loopback.
