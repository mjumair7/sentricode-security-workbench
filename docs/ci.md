# Use SentriCode in another repository

The CLI is enough for a local pre-push check:

```sh
sentricode scan /path/to/project --format json -o reports/report.json
sentricode baseline reports/report.json -o baseline.json
sentricode scan /path/to/project --baseline baseline.json --fail-on critical,high
```

The baseline makes the gate focus on newly introduced findings. It is not a permanent waiver: review it, commit it only when intentional, and refresh it as old findings are fixed. `sentricode compare reports/report.json --baseline baseline.json` reports the fingerprint differences. Keep detailed reports outside Git; this repository ignores `reports/`.

CLI exit codes are `0` for a completed passing scan, `1` for a failed finding policy, and `2` for an operational/required-engine failure. A report is still useful after a policy failure. Read its engine statuses before deciding that missing findings mean the project is safe.

## Reusable GitHub Actions workflow

Publish this scanner repository first. Copy the template below into `.github/workflows/security.yml` in another repository. Replace **every** occurrence of `YOUR-USERNAME` and `SCANNER_COMMIT_SHA` with your real scanner repository owner and a trusted full 40-character commit SHA. GitHub does not substitute those placeholders for you.

```yaml
name: Security checks
on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  sentricode:
    uses: YOUR-USERNAME/sentricode/.github/workflows/security-scan.yml@SCANNER_COMMIT_SHA
    with:
      scanner-repository: YOUR-USERNAME/sentricode
      scanner-ref: SCANNER_COMMIT_SHA
      fail-on: critical,high
      upload-sarif: false
```

Pin both the workflow reference and scanner reference. The scanner repository must be accessible to the caller; a public scanner repository is the simplest setup. Private reusable workflows require GitHub Actions access settings, and checking out a separate private scanner repository may need a separately scoped credential; that configuration is not wired into this template. [GitHub reusable workflow access](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations).

The workflow installs the trusted scanner in one directory and checks out the target repository in another. The target is treated as data: no target dependency installation, build, package import, test, or project script is run. On pull requests, the base commit is scanned first and becomes the baseline. Both scans use `--no-project-ignore`, so changing `.sentricodeignore` in a PR cannot hide its findings. It uses ordinary `pull_request` events; it does not use `pull_request_target` or execute PR code with deployment secrets. Checkout credentials are not persisted.

If you change the workflow, keep scanner installation separate from the target checkout. Do not install the scanner from the PR's modified source, and do not add a target build step to this scanning job. SentriCode's own separate build/test workflow necessarily tests its proposed application changes, on GitHub-hosted runners with a read-only token and no configured secrets. [GitHub workflow security guidance](https://docs.github.com/en/actions/reference/security/secure-use).

## SARIF and blocking merges

A `sentricode-sarif` artifact is retained for 14 days even when findings fail the policy. Set `upload-sarif: true` to send it to GitHub's Security → Code scanning view. Public repositories support third-party SARIF; private/internal repositories need the appropriate GitHub Code Security feature enabled. Leave upload off if unavailable; artifact download and the policy gate still work. [GitHub SARIF upload requirements](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file).

After the workflow has run once, add its check as a required status check in your branch protection/ruleset if you want to block merging failed scans. Merely adding a workflow does not enforce branch protection. Review action dependency updates and protect workflow/policy files in code review.

The dashboard policy is local to its database. To match it in a CLI workflow, pass the same flags or a reviewed JSON policy file with `fail_on`, `max_high`, and `fail_on_secrets`. The supplied `examples/policy.json` is a starting point. The reusable template intentionally uses only trusted workflow flags, not a policy that a target PR can silently loosen.

## Optional tools on a trusted machine

For an external engine, install Docker, pull and verify the image you intend to trust, and set its digest in the shell where you run the CLI:

```sh
export SENTRICODE_BANDIT_IMAGE='YOUR_VERIFIED_IMAGE@sha256:YOUR_64_HEX_DIGEST'
sentricode scan /path/to/project --external --require-engines Bandit --format json -o reports/external-report.json
```

The value is a template, not a runnable image name. Available variables are `SENTRICODE_SEMGREP_IMAGE`, `SENTRICODE_BANDIT_IMAGE`, `SENTRICODE_GITLEAKS_IMAGE`, `SENTRICODE_CHECKOV_IMAGE`, `SENTRICODE_TRIVY_IMAGE`, and `SENTRICODE_SYFT_IMAGE`. Containers use `--pull=never`; prepare images outside the scan. `--require-engines` turns a missing or skipped engine into a failing check; without it, unavailable optional tools are just reported as skipped. A Docker/Podman compatibility layer is not assumed.

For owner-controlled local checkouts only, `--local-tools` uses compatible scanner executables already on PATH. Add `--history` with Gitleaks enabled to scan a real Git checkout's history. Local Git history can contain real secrets that have already been deleted from current files; rotate them if found.

`--network` sends package identifiers and CVEs to advisory services. It does not install packages or send your repository to those services. Keep it off when dependency inventory itself is sensitive.
