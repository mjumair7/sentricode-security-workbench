# Start here

SentriCode runs on your computer and can scan your future projects. The core scanner does not need an AI subscription or API key.

## Run the full application

Install Docker Desktop and start it. Extract the source ZIP, open a terminal in the extracted `sentricode` folder, and run:

```sh
./scripts/configure
docker compose up -d --build
```

The configuration script prints your owner access token. Keep it private. Open **http://127.0.0.1:8000**, sign in, then choose **New scan** or **Try a sample**.

For later use, start Docker and run `docker compose up -d` in this folder. Your previous scan reports remain saved. Use `docker compose stop` to stop the app without deleting them.

On Windows, follow the [PowerShell instructions](docs/deployment.md#windows-powershell). If you prefer Python and Node without Docker, use the [source installation instructions](README.md#run-it).

## Put the code on GitHub

1. Extract the ZIP. Upload the extracted source, not the ZIP itself.
2. In GitHub Desktop, choose **File → Add local repository** and select the extracted folder. If it is not a repository yet, choose the offered **create a repository here** option.
3. Review the files, create the first commit, and select **Publish repository**.
4. Keep `.env`, access tokens, uploaded source, reports, and local databases out of GitHub. The included `.gitignore` excludes these generated and private files.

The README is already written in a personal voice around the Elevate (Nrth) seminar. Read it once and adjust anything you would phrase differently.

## Publish the running app

GitHub stores the code. A Linux server runs the application. Follow [the deployment guide](docs/deployment.md) for Docker, your domain, HTTPS, persistent reports, and owner authentication. The app has not been deployed to a public server for you.

## What this release covers

This is a working single-owner release: dashboard, source scanning, secret and confidentiality checks, dependency inventory, optional threat intelligence, optional AI guidance, CLI, scan comparisons, exports, policies, and GitHub Actions.

The original brief also describes enterprise and advanced features. [Coverage](docs/coverage.md) explicitly identifies those that are optional or deferred, including multi-user organizations, full cross-file analysis, image CVE scanning, and automatic fix pull requests.

## Optional prebuilt Python package

The separate `.whl` download includes the built dashboard, so this path needs Python 3.11+ but no Node build:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install /path/to/sentricode-0.1.0-py3-none-any.whl
.venv/bin/python -m uvicorn sentricode.api:app --host 127.0.0.1 --port 8000
```

Run from the same folder each time: reports are stored in its `data/` directory. Stop with Ctrl+C and repeat the last command to start again. This command listens only on your own computer. On Windows, use `.venv\Scripts\python.exe` instead of `.venv/bin/python`.
