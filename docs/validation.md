# Release verification

Verified on September 29, 2026 with Python 3.12.14 and Node.js 24.19.0.

- **142 automated tests passed.** The suite covers scanner findings and safe cases, resource limits, redaction, dependency parsing, mocked intelligence providers, CLI policy/baselines, exports, archive attacks, authentication/origin controls, concurrent queue submissions, lifecycle persistence, and worker recovery.
- **The Next.js production build and TypeScript checks passed.** The dashboard was exported and served by FastAPI.
- **Browser checks passed** for the empty workspace, sample scan, ZIP upload, real confidentiality finding, redacted secret evidence, local remediation guidance without an AI key, saved review decision, report history, engine coverage, and policy result. Desktop and mobile layouts were inspected.
- **The Python wheel was built** with the API, CLI, and compiled dashboard included. The source archive excludes credentials, installed dependencies, reports, and runtime databases.
- **CI baseline behavior was exercised locally:** unchanged findings passed the comparison; new findings failed, even when the scanned project tried to suppress checks through its ignore file.

The test run emitted one upstream FastAPI/Starlette warning about a future test-client dependency change. It did not affect the results.

Docker/Corepack were unavailable on this verification machine. Docker startup, a public HTTPS deployment, PostgreSQL, live GitHub OAuth/private imports, paid AI calls, and real optional scanner binaries/images were not exercised end to end. Provider flows have mocked tests; configuration and deployment files were reviewed. These are verification limits, not claims that those environments were tested.
