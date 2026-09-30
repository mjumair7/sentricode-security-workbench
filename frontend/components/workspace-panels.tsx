"use client";

import { useEffect, useState } from "react";
import {
  ArrowDownToLine,
  ArrowUpRight,
  Check,
  ChevronRight,
  Download,
  GitCompareArrows,
  Layers3,
  LoaderCircle,
  LockKeyhole,
  Printer,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
  Trash2,
} from "lucide-react";
import { api, date, exportUrl, humanize } from "@/lib/api";
import type { Audit, Comparison, Finding, Policy, Scan, Settings } from "@/lib/types";
import { Badge, Empty, ErrorNotice, FindingTable, Modal, Status } from "./ui";

export function HistoryPanel({
  scans,
  onSelect,
  onChange,
  notify,
}: {
  scans: Scan[];
  onSelect: (finding: Finding) => void;
  onChange: () => void;
  notify: (text: string) => void;
}) {
  const [selected, setSelected] = useState<Scan>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [baseline, setBaseline] = useState("");
  const [comparison, setComparison] = useState<Comparison>();
  const [confirmDelete, setConfirmDelete] = useState(false);
  useEffect(() => {
    if (!selected) return;
    const current = scans.find((scan) => scan.id === selected.id);
    if (current && (current.status !== selected.status || current.stage !== selected.stage)) {
      api<Scan>(`/scans/${current.id}`)
        .then(setSelected)
        .catch((err) => setError(err.message));
    }
  }, [scans, selected]);
  async function select(scan: Scan) {
    setLoading(true);
    setError("");
    setComparison(undefined);
    setBaseline("");
    try {
      setSelected(await api<Scan>(`/scans/${scan.id}`));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load scan.");
    } finally {
      setLoading(false);
    }
  }
  async function compare() {
    if (!selected || !baseline) return;
    setLoading(true);
    setError("");
    try {
      setComparison(
        await api<Comparison>(
          `/scans/${selected.id}/compare?baseline=${encodeURIComponent(baseline)}`,
        ),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Comparison failed.");
    } finally {
      setLoading(false);
    }
  }
  async function remove() {
    if (!selected) return;
    setLoading(true);
    try {
      await api(`/scans/${selected.id}`, { method: "DELETE" });
      setConfirmDelete(false);
      setSelected(undefined);
      onChange();
      notify("Scan and its saved results were deleted.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not delete scan.");
    } finally {
      setLoading(false);
    }
  }
  if (!scans.length)
    return (
      <Empty title="Your scan history starts here">
        Every completed scan keeps its findings, engine coverage, and downloadable reports.
      </Empty>
    );
  return (
    <>
      {error && <ErrorNotice>{error}</ErrorNotice>}
      <section className="panel">
        <div className="panel-heading">
          <h2>
            Scan timeline <span className="count-chip">{scans.length}</span>
          </h2>
          <span className="muted">Most recent first</span>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Project</th>
                <th>Started</th>
                <th>Mode</th>
                <th>Status</th>
                <th>Findings</th>
                <th>Posture</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr className={selected?.id === scan.id ? "selected-row" : ""} key={scan.id}>
                  <td>
                    <button className="finding-title" onClick={() => void select(scan)}>
                      {scan.repository_name}
                    </button>
                    <span className="file-label">{scan.id.slice(0, 8)}</span>
                  </td>
                  <td>{date(scan.created_at)}</td>
                  <td className="capitalize">{scan.mode}</td>
                  <td>
                    <Status status={scan.status} />
                  </td>
                  <td>{scan.summary?.total ?? "—"}</td>
                  <td>
                    <strong>{scan.summary?.score ?? "—"}</strong>
                    <span className="muted"> / 100</span>
                  </td>
                  <td>
                    <button
                      className="icon-button"
                      aria-label={`Inspect ${scan.repository_name} scan`}
                      onClick={() => void select(scan)}
                    >
                      <ChevronRight size={17} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      {loading && !selected && (
        <div className="inline-loader">
          <LoaderCircle className="spin" size={17} />
          Opening scan…
        </div>
      )}
      {selected && (
        <section className="panel scan-detail">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">SCAN DETAIL</span>
              <h2>{selected.repository_name}</h2>
              <p>
                {date(selected.created_at)} · {selected.files_scanned ?? 0} files ·{" "}
                {selected.duration_ms == null
                  ? "Duration unavailable"
                  : `${(selected.duration_ms / 1000).toFixed(2)}s`}
              </p>
            </div>
            <button
              className="icon-button danger"
              disabled={["running", "queued"].includes(selected.status)}
              aria-label="Delete saved scan"
              onClick={() => setConfirmDelete(true)}
            >
              <Trash2 size={17} />
            </button>
          </div>
          {selected.error && <ErrorNotice>{selected.error}</ErrorNotice>}
          {selected.policy && (
            <div className={`policy-result ${selected.policy.passed ? "passed" : "failed"}`}>
              <ShieldCheck size={19} />
              <div>
                <strong>
                  Quality gate {selected.policy.passed ? "passed" : "needs attention"}
                </strong>
                <p>
                  {selected.policy.passed
                    ? "Findings met the policy saved when this scan was queued."
                    : selected.policy.violations.join(" ")}
                </p>
                <span>
                  Scan-time policy snapshot. Reviewing a finding does not rewrite this result.
                </span>
              </div>
            </div>
          )}
          {selected.status === "completed" && (
            <>
              <div className="export-row">
                <span>
                  <Download size={15} /> Export report
                </span>
                {["json", "sarif", "csv", "sbom"].map((format) => (
                  <a
                    className="button small secondary"
                    key={format}
                    href={exportUrl(selected.id, format)}
                    download
                  >
                    {format === "sbom" ? "CycloneDX SBOM" : format.toUpperCase()}
                    <ArrowDownToLine size={13} />
                  </a>
                ))}
                <button className="button small secondary" onClick={() => window.print()}>
                  <Printer size={14} />
                  Print / PDF
                </button>
              </div>
              <div className="scan-details-grid">
                <div>
                  <h3>Engine coverage</h3>
                  <div className="engine-list">
                    {selected.engines?.map((engine, index) => (
                      <div className="engine-row" key={`${engine.name}-${index}`}>
                        <div>
                          <strong>{engine.name}</strong>
                          <p>{engine.message}</p>
                        </div>
                        <Status status={engine.status} />
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <h3>Languages & formats</h3>
                  <div className="language-list">
                    {Object.entries(selected.languages || {})
                      .sort((a, b) => b[1] - a[1])
                      .map(([language, count]) => (
                        <div key={language}>
                          <span>{language}</span>
                          <strong>{count} files</strong>
                        </div>
                      ))}
                  </div>
                  <p className="field-hint">
                    A file being counted does not mean every vulnerability class in that language is
                    covered.
                  </p>
                </div>
              </div>
              {!!selected.warnings?.length && (
                <div className="scan-warnings">
                  <h3>Coverage notes</h3>
                  <ul>
                    {selected.warnings.map((warning, index) => (
                      <li key={index}>{warning}</li>
                    ))}
                  </ul>
                </div>
              )}
              <div className="comparison-section">
                <div>
                  <GitCompareArrows size={18} />
                  <h3>SecureDiff</h3>
                  <span className="muted">Compare findings from two scans of this project</span>
                </div>
                <div className="button-row">
                  <select
                    value={baseline}
                    onChange={(event) => {
                      setBaseline(event.target.value);
                      setComparison(undefined);
                    }}
                    aria-label="Baseline scan"
                  >
                    <option value="">Choose a baseline scan</option>
                    {scans
                      .filter(
                        (scan) =>
                          scan.id !== selected.id &&
                          scan.repository_id === selected.repository_id &&
                          scan.status === "completed",
                      )
                      .map((scan) => (
                        <option value={scan.id} key={scan.id}>
                          {date(scan.created_at)} · {scan.id.slice(0, 8)}
                        </option>
                      ))}
                  </select>
                  <button
                    className="button secondary"
                    onClick={compare}
                    disabled={!baseline || loading}
                  >
                    Compare scans
                  </button>
                </div>
                {comparison && (
                  <>
                    <div className="diff-stats">
                      <span className="critical">+{comparison.new.length} introduced</span>
                      <span className="success-text">
                        −{comparison.resolved.length} no longer detected
                      </span>
                      <span>{comparison.unchanged} unchanged</span>
                    </div>
                    {comparison.new.length > 0 && (
                      <>
                        <h4>Introduced findings</h4>
                        <FindingTable findings={comparison.new} onSelect={onSelect} />
                      </>
                    )}
                    {comparison.resolved.length > 0 && (
                      <>
                        <h4>No longer detected</h4>
                        <FindingTable findings={comparison.resolved} onSelect={onSelect} />
                      </>
                    )}
                  </>
                )}
              </div>
              <div className="panel-heading">
                <h3>Findings in this scan</h3>
                <span className="muted">{selected.findings?.length ?? 0} total</span>
              </div>
              <FindingTable findings={selected.findings || []} onSelect={onSelect} />
            </>
          )}
        </section>
      )}
      <Modal
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title="Delete this saved scan?"
        description="The report, findings, and exports for this scan will be permanently removed. Your original repository is unaffected."
      >
        <div className="modal-footer">
          <button className="button secondary" onClick={() => setConfirmDelete(false)}>
            Keep scan
          </button>
          <button className="button danger-button" onClick={remove} disabled={loading}>
            Delete scan
          </button>
        </div>
      </Modal>
    </>
  );
}

export function DependenciesPanel({
  reports,
  findings,
  onSelect,
}: {
  reports: Scan[];
  findings: Finding[];
  onSelect: (finding: Finding) => void;
}) {
  const [query, setQuery] = useState("");
  const dependencies = reports.flatMap((report) =>
    (report.dependencies || []).map((dependency) => ({
      ...dependency,
      repository: report.repository_name,
      scanId: report.id,
    })),
  );
  const visible = dependencies.filter((dep) =>
    `${dep.name} ${dep.version} ${dep.ecosystem} ${dep.repository}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  const issues = findings.filter((item) => item.category === "dependencies");
  return (
    <>
      <div className="info-banner">
        <Layers3 size={22} />
        <div>
          <strong>
            {dependencies.length} recorded packages · {issues.length} vulnerability findings
          </strong>
          <p>
            Inventory comes from supported manifests and lockfiles. Known vulnerabilities are
            checked only when network lookups are enabled for a scan.
          </p>
        </div>
      </div>
      <div className="filter-toolbar">
        <label className="search-field">
          <Search size={16} />
          <input
            placeholder="Find a package or version…"
            aria-label="Search dependencies"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </label>
      </div>
      <section className="panel">
        <div className="panel-heading">
          <h2>
            Package inventory <span className="count-chip">{visible.length}</span>
          </h2>
          <span className="muted">Latest scans</span>
        </div>
        {visible.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Package</th>
                  <th>Version</th>
                  <th>Ecosystem</th>
                  <th>Project</th>
                  <th>Recorded vulnerabilities</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((dep, index) => {
                  const matches = issues.filter(
                    (item) =>
                      item.package?.name === dep.name && item.package?.version === dep.version,
                  );
                  return (
                    <tr key={`${dep.scanId}-${dep.name}-${dep.version}-${index}`}>
                      <td>
                        <strong className="package-name">{dep.name}</strong>
                        <span className="file-label">
                          {dep.file || dep.purl || "Manifest entry"}
                        </span>
                      </td>
                      <td>
                        <code>{dep.version}</code>
                      </td>
                      <td>{dep.ecosystem || "—"}</td>
                      <td>{dep.repository}</td>
                      <td>
                        {matches.length ? (
                          <button
                            className="text-button danger"
                            onClick={() => onSelect(matches[0])}
                          >
                            {matches.length} finding{matches.length === 1 ? "" : "s"}
                            <ArrowUpRight size={14} />
                          </button>
                        ) : (
                          <span className="muted">None recorded</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No packages in this view">
            Run a standard or deep scan with supported dependency manifests to build an inventory.
          </Empty>
        )}
      </section>
    </>
  );
}

export function SettingsPanel({
  settings,
  audit,
  onChange,
  notify,
}: {
  settings?: Settings;
  audit: Audit[];
  onChange: () => void;
  notify: (text: string) => void;
}) {
  const [policy, setPolicy] = useState<Policy>({
    fail_on: ["critical", "high"],
    max_high: 0,
    fail_on_secrets: true,
  });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    api<Policy>("/policy")
      .then(setPolicy)
      .catch((err) => setError(err.message));
  }, []);
  async function save(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      await api("/policy", { method: "PUT", body: JSON.stringify(policy) });
      notify("Quality gate policy saved.");
      onChange();
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save policy.");
    } finally {
      setBusy(false);
    }
  }
  function downloadPolicy() {
    const text = `fail_on: [${policy.fail_on.join(", ")}]\nmax_high: ${policy.max_high}\nfail_on_secrets: ${policy.fail_on_secrets}\n`;
    const href = URL.createObjectURL(new Blob([text], { type: "text/yaml" }));
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = ".sentricode.yml";
    anchor.click();
    URL.revokeObjectURL(href);
  }
  const integrations = [
    {
      title: "Workspace authentication",
      configured: settings?.auth_required,
      text: "An owner token protects shared or published instances.",
      env: "SENTRICODE_TOKEN",
    },
    {
      title: "AI explanations",
      configured: settings?.ai_configured,
      text: "Only runs when you request a review and give consent.",
      env: "OPENAI_API_KEY",
    },
    {
      title: "GitHub sign-in",
      configured: settings?.github_configured,
      text: "Optional OAuth sign-in for the configured workspace owner.",
      env: "SENTRICODE_GITHUB_CLIENT_ID",
    },
    {
      title: "Vulnerability intelligence",
      configured: settings?.network_enabled,
      text: "Allows per-scan package and CVE lookups; source stays local.",
      env: "SENTRICODE_NETWORK_ENABLED",
    },
  ];
  return (
    <>
      <div className="settings-grid">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Privacy & integrations</h2>
              <p>Configure credentials on the server, never in your browser.</p>
            </div>
            <LockKeyhole size={19} />
          </div>
          <div className="integration-list">
            {integrations.map((item) => (
              <div className="integration-row" key={item.title}>
                <div>
                  <strong>{item.title}</strong>
                  <p>{item.text}</p>
                  <code>{item.env}</code>
                </div>
                <span className={`connection-label ${item.configured ? "enabled" : ""}`}>
                  {item.configured ? "Configured" : "Off"}
                </span>
              </div>
            ))}
          </div>
          <div className="setting-footnote">
            Edit your <code>.env</code> file and restart SentriCode to change integrations. Keys are
            never returned by this page.
          </div>
        </section>
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Security quality gate</h2>
              <p>Save your workspace policy and use it in future CI runs.</p>
            </div>
            <SlidersHorizontal size={19} />
          </div>
          <form className="policy-form" onSubmit={save}>
            <fieldset>
              <legend>Fail on these severities</legend>
              <div className="policy-severities">
                {["critical", "high", "medium", "low"].map((severity) => (
                  <label key={severity} className="check-row">
                    <input
                      type="checkbox"
                      checked={policy.fail_on.includes(severity)}
                      onChange={(event) =>
                        setPolicy({
                          ...policy,
                          fail_on: event.target.checked
                            ? [...policy.fail_on, severity]
                            : policy.fail_on.filter((item) => item !== severity),
                        })
                      }
                    />
                    <span className="capitalize">{severity}</span>
                  </label>
                ))}
              </div>
            </fieldset>
            <label className="field">
              Maximum high-severity findings
              <input
                type="number"
                min={0}
                max={10000}
                step={1}
                value={policy.max_high}
                onChange={(event) =>
                  setPolicy({ ...policy, max_high: Math.max(0, Number(event.target.value)) })
                }
              />
              <span className="field-hint">
                Applies when “high” is selected in the fail-on list.
              </span>
            </label>
            <label className="check-row">
              <input
                type="checkbox"
                checked={policy.fail_on_secrets}
                onChange={(event) =>
                  setPolicy({ ...policy, fail_on_secrets: event.target.checked })
                }
              />
              <span>Fail when an exposed secret is found</span>
            </label>
            {error && <ErrorNotice>{error}</ErrorNotice>}
            <div className="button-row">
              <button className="button primary" disabled={busy}>
                {busy ? <LoaderCircle size={15} className="spin" /> : <Check size={15} />}Save
                policy
              </button>
              <button className="button secondary" type="button" onClick={downloadPolicy}>
                <Download size={15} />
                Download YAML
              </button>
            </div>
            <p className="field-hint">
              Add the downloaded <code>.sentricode.yml</code> to your repository. The CLI reads it
              when you pass <code>--policy .sentricode.yml</code>.
            </p>
          </form>
        </section>
      </div>
      <section className="panel cli-panel">
        <div>
          <Terminal size={22} />
          <h2>Take these checks into your next project.</h2>
          <p>
            The CLI works independently of this dashboard. Install it once, then run it from your
            own repositories.
          </p>
        </div>
        <pre>
          <code>sentricode scan . --format sarif --output sentricode.sarif</code>
        </pre>
      </section>
      <section className="panel">
        <div className="panel-heading">
          <h2>Audit trail</h2>
          <span className="muted">Recent workspace events</span>
        </div>
        {audit.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Resource</th>
                  <th>Time</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {audit.slice(0, 50).map((event) => (
                  <tr key={event.id}>
                    <td>
                      <strong>{humanize(event.action)}</strong>
                    </td>
                    <td className="mono muted">{event.resource?.slice(0, 20) || "workspace"}</td>
                    <td>{date(event.created_at)}</td>
                    <td className="audit-detail">
                      {typeof event.detail === "string"
                        ? event.detail
                        : JSON.stringify(event.detail)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="no-activity">
            Actions such as starting scans and reviewing findings are recorded here.
          </p>
        )}
      </section>
    </>
  );
}
