# Publishing SentriCode

There are two things to publish: the source repository, and a running private application. You can publish the source while keeping the scanner itself accessible only to you.

## Put the code on GitHub

Extract the ZIP first. Upload the files inside the `sentricode` folder, rather than storing only a ZIP in the repository.

With GitHub Desktop, choose **File → Add local repository**, select the extracted folder, and choose **create a repository here** if it has no Git history. Review the files, commit them, then choose **Publish repository**. Pick public for a portfolio or private for personal use. The `.github` folder contains the CI workflows and should be included.

With Git, create an empty repository on GitHub without an extra README or license, then run this inside the extracted folder. Replace the URL with your own repository:

```sh
git init
git add .
git status
git commit -m "Build SentriCode security workbench"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/sentricode.git
git push -u origin main
```

Check `git status` before the commit. `.gitignore` excludes your `.env`, scan data, dependencies, local builds, and ZIPs. Do not put real credentials into example files. If a credential has already been committed, removing it from a later commit is not enough: rotate it at the provider.

The first Actions run builds the dashboard, runs the Python tests, and checks the Docker build. The security workflow also keeps a SARIF artifact. GitHub's code-scanning UI is optional; see [CI integration](ci.md).

## Run privately on your computer

```sh
./scripts/configure
docker compose up -d --build
```

Save the owner token printed by `scripts/configure`, open http://127.0.0.1:8000, and sign in. The script creates `.env` with a random token; if `.env` already exists, it preserves it and you must fill in any missing token yourself. The published port is bound to loopback, so another computer cannot connect to it through your network address. Docker requires a token because incoming requests pass through its network bridge.

To generate a replacement token for `.env`:

```sh
python3 -c "import secrets; print(secrets.token_urlsafe(36))"
```

Store this token in your password manager. It is your owner credential; changing it invalidates signed browser sessions. The generated token must be at least 24 characters.

### Windows PowerShell

Docker Desktop's Linux-container mode can run the application. Configure it without a Bash shell:

```powershell
Copy-Item .env.example .env
docker run --rm python:3.12-slim python -c "import secrets; print(secrets.token_urlsafe(36))"
notepad .env
```

Paste the generated token after `SENTRICODE_TOKEN=`, save the file, then run `docker compose up -d --build`. Open http://127.0.0.1:8000 and sign in with that token. Keep an existing `.env` rather than replacing it on later runs.

## Publish on a Linux server with HTTPS

Use a server with Docker Engine and the Compose plugin, a hostname pointed at that server, and enough disk space for reports. A small machine with 2 CPU cores and 2 GB RAM is a reasonable starting point, not a measured capacity guarantee. Building the frontend can need more memory than running the final service; if the build is killed, build on a larger machine or add memory.

1. Point the hostname's DNS A record at the server's public IPv4 address. Only add an AAAA record if IPv6 actually reaches the server.
2. Allow inbound TCP 80 and 443 in the server firewall and provider firewall. Keep SSH restricted to your normal administration access. Port 8000 stays bound to loopback.
3. Clone your repository, enter its folder, and run `./scripts/configure` to generate `.env` and an owner token.
4. Set these three values in `.env`:

```dotenv
SENTRICODE_DOMAIN=security.your-domain.com
SENTRICODE_PUBLIC_URL=https://security.your-domain.com
SENTRICODE_TOKEN=REPLACE_WITH_THE_RANDOM_TOKEN_YOU_GENERATED
```

5. Start the application and proxy:

```sh
docker compose -f compose.yaml -f compose.production.yaml up -d --build
docker compose -f compose.yaml -f compose.production.yaml ps
```

Open your HTTPS address and sign in with the owner token. Caddy obtains and renews the certificate when the domain resolves correctly and ports 80/443 are reachable. The backend rejects a non-local public URL unless it uses HTTPS and has a sufficiently long token. That check does not replace your firewall or TLS setup. [Caddy HTTPS requirements](https://caddyserver.com/docs/automatic-https).

The server remains independent of your computer and any chat session. Docker's restart policy brings it back after a server restart if Docker is enabled at boot. For an intentional stop or restart, keep using the same pair of Compose files:

```sh
docker compose -f compose.yaml -f compose.production.yaml stop
docker compose -f compose.yaml -f compose.production.yaml up -d
```

Do not put this personal single-owner deployment behind a public anonymous upload page. Organizations, per-user access control, hosted abuse controls, and tenant isolation are outside this release.

## Optional GitHub access

Public repository imports need no GitHub sign-in. To import private repositories, add `SENTRICODE_GITHUB_TOKEN` with read-only access limited to the repositories you need. The token is used on the server for GitHub downloads and never returned to the dashboard.

For GitHub owner sign-in, create a GitHub OAuth App. Use your public URL as its homepage and register this exact callback:

```text
https://security.your-domain.com/api/v1/auth/github/callback
```

Set `SENTRICODE_GITHUB_CLIENT_ID`, `SENTRICODE_GITHUB_CLIENT_SECRET`, and `SENTRICODE_GITHUB_OWNER` to your GitHub login. Keep `SENTRICODE_TOKEN` configured; it signs sessions and remains a fallback sign-in method. OAuth sign-in is restricted to that one login and does not grant access to every GitHub user. Restart/recreate the service after changing settings. See [GitHub OAuth app registration](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app).

## Optional AI and vulnerability intelligence

Set `OPENAI_API_KEY` to enable provider-backed explanations, and choose an available model through `SENTRICODE_AI_MODEL`. A finding's analysis action asks for consent before sending its redacted context. Review that context and use local guidance for projects you cannot share with an external provider.

Set `SENTRICODE_NETWORK_ENABLED=true` to allow users of your instance to opt into OSV and exploit-intelligence lookups on a scan. The per-scan switch is still required. GitHub repository download is a separate explicit network operation. See the [data handling table](security.md#where-data-goes).

## Storage, backups, and updates

SQLite and reports use the named `sentricode-data` volume. Downloaded/extracted source is temporary and is removed after a scan. Named volumes survive recreating containers and `docker compose down`; `down -v` deletes them. [Docker volume documentation](https://docs.docker.com/reference/compose-file/volumes/).

For a consistent local SQLite backup, stop the app before copying the data. These commands create a timestamped backup folder on the host; protect it like the live reports:

```sh
docker compose stop app
mkdir -p backups
docker compose cp app:/data "./backups/data-$(date +%Y%m%d-%H%M%S)"
docker compose up -d app
```

For the HTTPS deployment, add `-f compose.yaml -f compose.production.yaml` after `docker compose`. To restore, stop the app, replace the contents of its `/data` volume with the saved data, and ensure ownership is UID/GID `10001:10001` before restarting. Keep a separate copy before a restore. For PostgreSQL, use the database provider's consistent backup/restore facilities instead of copying database files.

Before updating, back up your data and read the changes. Then pull your reviewed commit and rebuild:

```sh
git pull --ff-only
docker compose -f compose.yaml -f compose.production.yaml up -d --build
```

The initial schema is created automatically. There is no migration framework in this release; a future schema-changing release must include a migration before you apply it to existing data. Do not assume changing an environment variable migrates SQLite to PostgreSQL.

## PostgreSQL and a separate worker

The Docker image includes the PostgreSQL driver. To use a database you have already provisioned, set `SENTRICODE_DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST:5432/DBNAME`. URL-encode reserved characters in credentials, restrict database access to the application, and configure TLS using your provider's connection requirements. The app creates its tables in an empty database.

The default process runs an embedded worker. `docker compose -f compose.yaml -f compose.worker.yaml up -d --build` moves work into a separate container sharing the data volume and disables the embedded worker. Add `-f compose.production.yaml` for HTTPS. Stop both the app and worker before taking a backup.

A separately supervised worker uses `python -m sentricode.worker`; set `SENTRICODE_EMBEDDED_WORKER=false` on the API, and provide the same database and jobs directory to both processes. Job claims are atomic and workers send heartbeats, but keep one worker until you have tested your deployment's concurrency and recovery behavior. This is not a distributed object-storage architecture.

## Troubleshooting

- **The page will not load locally:** wait for `docker compose ps` to show a healthy app, then inspect `docker compose logs app`. Make sure Docker is running and port 8000 is free.
- **The certificate will not issue:** check DNS, both firewalls, and `docker compose -f compose.yaml -f compose.production.yaml logs caddy`.
- **Sign-in works but actions are rejected:** `SENTRICODE_PUBLIC_URL` must match the browser origin exactly, including HTTPS and any nonstandard port. Add explicit extra origins only when you intentionally use another frontend.
- **A scanner is skipped:** open the scan's engine status. The web service intentionally does not have a Docker socket; use the CLI on a trusted workstation for optional container adapters.
- **A dependency has no vulnerability result:** inventory alone is not an advisory check. Enable network lookups for resolved versions and check for lookup failures.
- **A scan fails or a report looks incomplete:** use its warnings and engine statuses; do not treat partial coverage as a clean security result.
