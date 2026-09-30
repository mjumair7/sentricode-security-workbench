# Rules I maintain

The built-in Python rules live in `backend/sentricode/analysis/sast.py`; the secret patterns and redaction logic live in `analysis/common.py`. I keep the rule IDs stable so a finding can survive a line-number change and still match a reviewed baseline.

The optional Semgrep adapter uses the small, trusted pack embedded in `analysis/external.py`. It does not fetch a rule registry or execute rules supplied by an uploaded repository. These rules supplement the built-in checks; they are not the entire Semgrep registry.

Python analysis follows direct input expressions and local assignments inside a function. JavaScript/TypeScript and infrastructure checks are lexical review findings. Neither provides whole-program proof, framework-level authorization analysis, or a guarantee that a clean result means secure code.

Add a rule with a stable ID, evidence, CWE mapping, severity, remediation, and both vulnerable and safe tests. Keep evidence redaction at the shared reporting boundary.
