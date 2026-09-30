# Security model and data handling

This release is designed for one owner scanning projects they are authorized to inspect. It is not a public anonymous analysis service or a multi-tenant security product.

## What a scan is allowed to do

Built-in scanning reads text, parses syntax/manifests, and emits findings. It does not import the target Python package, install target dependencies, run target scripts, start target services, execute tests, or build target containers. GitHub import downloads a source archive rather than cloning with hooks or submodules.

ZIP ingestion rejects traversal paths, links, special files, encrypted members, duplicate paths, suspicious compression ratios, and archives beyond configured limits. The defaults are 25 MiB compressed, 100 MiB expanded, 20 MiB per archive member, and 10,000 entries. The scanner has additional independent reading limits: 6,000 files, 2 MiB per file, and 64 MiB of text. Increasing upload limits does not increase scanner coverage limits. Source symlinks, binary content, generated/vendor directories, and unsupported text encodings are skipped.

Built-in parsers run in the worker process. Docker wraps that process in the application container, with a non-root user, dropped capabilities, read-only root filesystem, bounded resources, and writable data/tmp locations. There is **no separate container per uploaded repository**, and a parser defect would share the worker's trust boundary. Do not describe this deployment as hardened isolation for mutually untrusted tenants.

## Optional external tools

External adapters are CLI-only. `--external` invokes fixed tool commands in owner-configured, pre-pulled images pinned by SHA-256 digest. Containers have no network, read-only source/config mounts, no added capabilities, a non-root user, process/memory/CPU limits, and a timeout. Images and scanner binaries are not bundled or downloaded automatically.

`--local-tools` is a separate explicit choice for an owner-controlled checkout. Installed tools run as your user without the container isolation above. Their behavior and any vulnerabilities in their parsers are part of your machine's trust boundary. Do not use that option for arbitrary repositories from strangers.

The hosted image does not include the Docker CLI or mount the host's Docker socket. Adding the socket would grant extensive host control and is outside the supplied deployment model.

## Where data goes

| Action | Data sent | Destination |
|---|---|---|
| Built-in scan, network off | No source or findings sent externally | Local worker and database |
| ZIP upload to your hosted app | The ZIP's full contents | Your server |
| GitHub import | Repository name/ref and optional GitHub read token | GitHub API; archive downloaded from GitHub codeload |
| Optional advisory queries | Package names, ecosystems, exact versions | OSV API |
| Optional EPSS query | CVE identifiers | FIRST EPSS API |
| Optional KEV lookup | Downloads a public catalog | CISA |
| AI explanation with consent | One finding's limited redacted metadata/evidence | OpenAI Responses API |
| GitHub OAuth | OAuth exchange and owner identity lookup | GitHub |
| SARIF upload in CI | Findings and source locations in the exported report | GitHub |

The global network setting gates vulnerability intelligence, and each scan must also opt in. A requested GitHub import still performs its necessary download with the setting off. AI and OAuth have separate, explicit configuration. `store=false` on AI requests does not override the provider's retention or abuse-monitoring policies.

Package inventories can themselves reveal information about a private project. Enable network services only where sharing that information is acceptable.

## Secrets and stored reports

Known credential patterns and detected secret values are redacted before report persistence and export. AI context has another redaction pass; secret-category evidence is withheld entirely. This is a best-effort pattern-based control: an unknown secret or sensitive business logic may remain in a normal code snippet. Inspect what you share and keep AI disabled for source that cannot leave your environment.

Full checkouts are temporary. The database retains redacted snippets, filenames, package metadata, finding status/reasons, scan results, and audit records. The filesystem volume and database are not encrypted by the application. Use host disk encryption or encrypted managed storage and protect backups. Uploaded source can exist in queued/running jobs and after a process crash until cleanup/recovery.

Environment credentials are read on the server. `.env` is excluded from Git and image build context; `scripts/configure` creates it with restrictive file permissions. Protect it and your process/container access. Rotating a key at the provider is still required if it was exposed.

## Authentication and browser requests

The personal workspace accepts one owner token, at least 24 characters when configured. Signed sessions expire after 12 hours and use HttpOnly, SameSite=Strict cookies; HTTPS deployments also set Secure. Changing the owner token invalidates sessions. Optional GitHub OAuth uses state validation and only accepts the configured GitHub owner login; it is not open registration.

Direct tokenless operation is limited to loopback clients and intended for your own computer. Docker requires a token because its bridge is not loopback. Public URLs require HTTPS and a token. Host validation, same-origin checks for mutations, same-site cookies, no cross-origin API access, bounded request bodies, and per-process request throttling provide additional defenses.

The rate limiter is process-local, does not persist across restarts, and sees the proxy as the client in the supplied deployment. It is useful for a personal instance, not distributed abuse prevention. The application uses a static-export-compatible CSP that permits inline script/style data; it is not a nonce-based strict CSP.

## Findings and review

Findings are leads, not verified exploit demonstrations. Narrow patterns miss issues and sometimes flag safe code. False-positive and accepted-risk decisions require a reason and are recorded in the audit log. Audit records are regular database rows, not tamper-evident or immutable logs. Source deletion does not automatically remove exported reports or backups.

AI text cannot automatically suppress findings or execute patches. It has no tools to follow repository instructions. Prompt injection can still influence generated prose, so review suggestions and verify them with the target application's own tests in an environment you trust.

See [coverage](coverage.md) for analysis limits and [SECURITY.md](../SECURITY.md) for reporting a problem in SentriCode itself.
