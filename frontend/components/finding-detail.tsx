"use client";

import { useState } from "react";
import {
  ArrowDown,
  Check,
  ExternalLink,
  GitBranch,
  LoaderCircle,
  LockKeyhole,
  Sparkles,
} from "lucide-react";
import { api, humanize } from "@/lib/api";
import type { Analysis, Finding, FindingStatus, Settings } from "@/lib/types";
import { Badge, ErrorNotice, Modal } from "./ui";

const states: FindingStatus[] = [
  "open",
  "confirmed",
  "in_progress",
  "resolved",
  "accepted_risk",
  "false_positive",
];

export function FindingDetail({
  finding,
  onClose,
  onChange,
  settings,
}: {
  finding: Finding;
  onClose: () => void;
  onChange: () => void;
  settings?: Settings;
}) {
  const [tab, setTab] = useState("evidence");
  const [status, setStatus] = useState(finding.status);
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [consent, setConsent] = useState(false);
  const [audience, setAudience] = useState("developer");
  const [analysis, setAnalysis] = useState<Analysis>();
  async function update() {
    setBusy(true);
    setError("");
    try {
      await api(`/findings/${finding.id}`, {
        method: "PATCH",
        body: JSON.stringify({ status, reason }),
      });
      setSaved(true);
      onChange();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not update the finding.");
    } finally {
      setBusy(false);
    }
  }
  async function explain() {
    setBusy(true);
    setError("");
    try {
      setAnalysis(
        await api<Analysis>(`/findings/${finding.id}/analysis`, {
          method: "POST",
          body: JSON.stringify({ audience, consent: settings?.ai_configured ? consent : true }),
        }),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not generate guidance.");
    } finally {
      setBusy(false);
    }
  }
  const validReferences = (finding.references || []).filter((url) => /^https:\/\//.test(url));
  return (
    <Modal
      wide
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={finding.title}
      description={`${finding.file}:${finding.line_start} · ${finding.rule_id}`}
    >
      <div className="detail-meta">
        <Badge severity={finding.severity} />
        <span className="risk-pill">
          SentriScore <strong>{finding.sentri_score}</strong> / 100
        </span>
        <span>{Math.round(finding.confidence * 100)}% rule confidence</span>
      </div>
      <p className="description">{finding.description}</p>
      <div className="standard-grid">
        <div>
          <span>WEAKNESS</span>
          <strong>{finding.cwe || "Not mapped"}</strong>
        </div>
        <div>
          <span>OWASP</span>
          <strong>{finding.owasp || "Not mapped"}</strong>
        </div>
        <div>
          <span>DETECTED BY</span>
          <strong>{finding.scanner}</strong>
        </div>
        <div>
          <span>KNOWN EXPLOITED</span>
          <strong>
            {finding.kev == null ? "Not checked" : finding.kev ? "Yes · CISA KEV" : "Not listed"}
          </strong>
        </div>
      </div>
      {finding.cve && (
        <div className="intelligence">
          <strong>{finding.cve}</strong>
          <span>CVSS {finding.cvss ?? "unavailable"}</span>
          <span>
            EPSS {finding.epss == null ? "unavailable" : `${(finding.epss * 100).toFixed(2)}%`}
          </span>
        </div>
      )}
      <div className="detail-tabs" role="tablist" aria-label="Finding details">
        {[
          { id: "evidence", text: "Evidence" },
          { id: "remediation", text: "Remediation" },
          { id: "flow", text: "Data flow" },
          { id: "ai", text: "AI review" },
          { id: "review", text: "Triage" },
        ].map((item) => (
          <button
            role="tab"
            aria-selected={tab === item.id}
            key={item.id}
            onClick={() => setTab(item.id)}
            className={tab === item.id ? "active" : ""}
          >
            {item.text}
          </button>
        ))}
      </div>
      <div className="detail-content" role="tabpanel">
        {tab === "evidence" && (
          <>
            <div className="code-heading">
              <span>{finding.file}</span>
              <span>
                {finding.language} · line {finding.line_start}
              </span>
            </div>
            <pre className="code-evidence">
              <code>{finding.evidence || "No source excerpt retained for this finding."}</code>
            </pre>
            <p className="field-hint">
              <LockKeyhole size={13} /> Matching secret values are redacted before results are
              saved. Pattern matches still need your review.
            </p>
          </>
        )}
        {tab === "remediation" && (
          <>
            <h3>Recommended next step</h3>
            <p className="prose-text">{finding.remediation}</p>
            {validReferences.length > 0 && (
              <div className="references">
                <h4>References</h4>
                {validReferences.map((url) => (
                  <a key={url} href={url} target="_blank" rel="noreferrer">
                    {new URL(url).hostname}
                    <ExternalLink size={14} />
                  </a>
                ))}
              </div>
            )}
            <p className="field-hint">
              Make the change in your project, run its tests, then scan it again.
            </p>
          </>
        )}
        {tab === "flow" &&
          ((finding.data_flow || []).length ? (
            <>
              <div className="flow">
                {finding.data_flow.map((node, index) => (
                  <div key={index}>
                    {index > 0 && <ArrowDown size={20} />}
                    <div className={`flow-node ${node.kind}`}>
                      <span>{humanize(node.kind)}</span>
                      <strong>{node.label}</strong>
                      {node.file && (
                        <small>
                          {node.file}:{node.line}
                        </small>
                      )}
                    </div>
                  </div>
                ))}
              </div>
              <p className="field-hint">
                This is the rule&apos;s observed or inferred flow, not proof of runtime
                reachability.
              </p>
            </>
          ) : (
            <div className="empty-inline">
              <GitBranch size={25} />
              <h3>No flow recorded</h3>
              <p>This rule reports a pattern without tracing a source-to-sink path.</p>
            </div>
          ))}
        {tab === "ai" && (
          <>
            <div className="ai-heading">
              <Sparkles size={21} />
              <div>
                <h3>
                  {settings?.ai_configured
                    ? "Request a second opinion"
                    : "Local remediation guidance"}
                </h3>
                <p>
                  {settings?.ai_configured
                    ? "Only this finding and its redacted excerpt are sent to the configured model."
                    : "No AI provider is configured. You can still review the scanner’s remediation guidance."}
                </p>
              </div>
            </div>
            <label className="field">
              Explanation style
              <select value={audience} onChange={(event) => setAudience(event.target.value)}>
                <option value="developer">Developer</option>
                <option value="beginner">Getting started</option>
                <option value="security">Security engineer</option>
              </select>
            </label>
            {settings?.ai_configured && (
              <label className="check-row">
                <input
                  type="checkbox"
                  checked={consent}
                  onChange={(event) => setConsent(event.target.checked)}
                />
                <span>I agree to send this redacted finding to the configured AI provider.</span>
              </label>
            )}
            <button
              className="button primary"
              onClick={explain}
              disabled={busy || (!!settings?.ai_configured && !consent)}
            >
              {busy ? <LoaderCircle size={16} className="spin" /> : <Sparkles size={16} />}
              {settings?.ai_configured ? "Generate review" : "Show guidance"}
            </button>
            {analysis && (
              <div className="analysis-result">
                <span className="eyebrow">
                  {analysis.provider === "local"
                    ? "SCANNER GUIDANCE · NO AI USED"
                    : `AI DRAFT · ${analysis.provider}`}
                </span>
                <p className="prose-text">{analysis.analysis}</p>
                {analysis.patch && (
                  <>
                    <h4>Suggested patch · review before applying</h4>
                    <pre>
                      <code>{analysis.patch}</code>
                    </pre>
                  </>
                )}
                {analysis.tests && (
                  <>
                    <h4>Suggested regression test</h4>
                    <pre>
                      <code>{analysis.tests}</code>
                    </pre>
                  </>
                )}
                {analysis.warning && <p className="field-hint">{analysis.warning}</p>}
              </div>
            )}
          </>
        )}
        {tab === "review" && (
          <>
            <h3>Record your decision</h3>
            <p className="field-hint">
              Triage changes are saved to the audit log. They do not change your source code.
            </p>
            <label className="field">
              Status
              <select
                value={status}
                onChange={(event) => {
                  setStatus(event.target.value as FindingStatus);
                  setSaved(false);
                }}
              >
                {states.map((state) => (
                  <option key={state} value={state}>
                    {humanize(state)}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              Review note
              <textarea
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                rows={3}
                placeholder="Why this decision makes sense for this project…"
              />
            </label>
            <button
              className="button primary"
              onClick={update}
              disabled={
                busy ||
                (["resolved", "accepted_risk", "false_positive"].includes(status) && !reason.trim())
              }
            >
              {busy ? <LoaderCircle size={16} className="spin" /> : <Check size={16} />}
              {saved ? "Decision saved" : "Save decision"}
            </button>
          </>
        )}
        {error && <ErrorNotice>{error}</ErrorNotice>}
      </div>
    </Modal>
  );
}
