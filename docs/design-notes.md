# Design notes

This is a short record of the choices that shaped SentriCode. It is intentionally less formal than the architecture documentation.

## Why build another scanner?

I did not set out to compete with mature security tools. I wanted to learn the workflow around them: controlled ingestion, evidence handling, scan history, policy gates, and communicating uncertainty to a developer.

That changed the scope. A small set of understandable checks with visible limits was more useful to me than a large list of rules I could not explain.

## Why local first?

Source code is sensitive input. The default workflow keeps it on the machine running SentriCode. Network features are separate and optional:

- GitHub import fetches a repository the user explicitly selected.
- vulnerability enrichment contacts configured external services;
- AI guidance sends only the redacted context for one selected finding.

The scanner still works when all three are disabled.

## Why keep ingestion limits separate?

An upload limit alone is not enough. A small compressed archive can expand dramatically, and a repository can contain thousands of generated files. SentriCode therefore limits compressed bytes, expanded bytes, members, files read, bytes per file, and total decoded text independently.

Symlinks and special archive entries are rejected rather than followed. Vendor, generated, and VCS directories are skipped because they add noise and consume the reading budget.

## Why show failed and skipped engines?

Early in the project, it was tempting to return a single list of findings. That makes an empty list ambiguous: did the check pass, or did the engine never run?

Each engine now reports a status and message. The report can be useful even when an optional engine is unavailable, but the missing coverage stays visible.

## Why no automatic patching?

A suggested fix can be wrong even when the finding is real. SentriCode keeps the trust boundary simple: scanners produce evidence, people decide what it means, and the target project's own tests verify the eventual change.

AI text follows the same rule. It can explain a selected finding, but it cannot execute code, suppress the finding, or modify a repository.

## What I would improve next

1. Replace selected pattern checks with deeper language-aware analysis.
2. Add integration tests around PostgreSQL and the worker deployment.
3. Make large scan comparisons easier to filter and navigate.
4. Add signed release artifacts and a documented upgrade path.
5. Revisit authentication only if the project grows beyond its single-owner model.

These are future directions, not finished features.
