"use client";

import { useCallback, useEffect, useState, type CSSProperties } from "react";
import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  BookOpen,
  Check,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Code2,
  FileCode2,
  FolderGit2,
  GitFork,
  Layers3,
  LayoutDashboard,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  Menu,
  Plus,
  RefreshCw,
  Search,
  Settings2,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
  X,
} from "lucide-react";
import { api, date, humanize } from "@/lib/api";
import type { Audit, Finding, Repository, Scan, Session, Settings } from "@/lib/types";
import { Brand, Empty, ErrorNotice, FindingTable, Status } from "./ui";
import { NewScan } from "./new-scan";
import { FindingDetail } from "./finding-detail";
import { DependenciesPanel, HistoryPanel, SettingsPanel } from "./workspace-panels";
import { RepositoryPicker } from "./repository-picker";

type Page =
  | "overview"
  | "repositories"
  | "findings"
  | "privacy"
  | "dependencies"
  | "history"
  | "settings";
const navigation: { id: Page; label: string; icon: typeof Shield }[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "repositories", label: "Repositories", icon: FolderGit2 },
  { id: "findings", label: "Findings", icon: ShieldCheck },
  { id: "privacy", label: "DataGuard", icon: LockKeyhole },
  { id: "dependencies", label: "Dependencies", icon: Layers3 },
  { id: "history", label: "Scan history", icon: Activity },
];
const activeStatuses = new Set(["open", "confirmed", "in_progress"]);
const categories = [
  { id: "sast", title: "Code security", icon: FileCode2 },
  { id: "secrets", title: "Exposed secrets", icon: LockKeyhole },
  { id: "dependencies", title: "Dependencies", icon: Layers3 },
  { id: "iac", title: "Infrastructure", icon: SlidersHorizontal },
  { id: "privacy", title: "Confidentiality", icon: Shield },
];

export function Workspace() {
  const [page, setPage] = useState<Page>("overview");
  const [session, setSession] = useState<Session>();
  const [settings, setSettings] = useState<Settings>();
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [reports, setReports] = useState<Scan[]>([]);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [scope, setScope] = useState("all");
  const [finding, setFinding] = useState<Finding>();
  const [newScan, setNewScan] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [category, setCategory] = useState("all");
  const [status, setStatus] = useState("active");
  const [toast, setToast] = useState("");

  const refresh = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const [nextScans, nextRepositories, nextSettings, nextAudit] = await Promise.all([
        api<Scan[]>("/scans"),
        api<Repository[]>("/repositories"),
        api<Settings>("/settings"),
        api<Audit[]>("/audit"),
      ]);
      setScans(nextScans);
      setRepositories(nextRepositories);
      setSettings(nextSettings);
      setAudit(nextAudit);
      const latest = new Map<string, Scan>();
      for (const scan of nextScans)
        if (scan.status === "completed" && !latest.has(scan.repository_id))
          latest.set(scan.repository_id, scan);
      setReports(
        await Promise.all([...latest.values()].map((scan) => api<Scan>(`/scans/${scan.id}`))),
      );
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not reach the API.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const saved = window.location.hash.slice(1) as Page;
    if ([...navigation.map((item) => item.id), "settings"].includes(saved)) setPage(saved);
    api<Session>("/auth/session")
      .then((current) => {
        setSession(current);
        if (!current.login_required || current.authenticated) void refresh();
        else setLoading(false);
      })
      .catch(() => {
        setError(
          "The workspace could not connect to the API. Start SentriCode and reload this page.",
        );
        setLoading(false);
      });
  }, [refresh]);
  const running = scans.filter((scan) => ["queued", "running"].includes(scan.status));
  useEffect(() => {
    if (!running.length) return;
    const timer = setInterval(() => void refresh(true), 2500);
    return () => clearInterval(timer);
  }, [running.length, refresh]);
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(""), 5000);
    return () => clearTimeout(timer);
  }, [toast]);

  function navigate(next: Page) {
    setPage(next);
    window.location.hash = next;
    setMobileNav(false);
  }
  const scopedReports = reports.filter(
    (report) => scope === "all" || report.repository_id === scope,
  );
  const scopedScans = scans.filter((scan) => scope === "all" || scan.repository_id === scope);
  const allFindings = scopedReports
    .flatMap((report) => report.findings || [])
    .sort((a, b) => b.sentri_score - a.sentri_score);
  const activeFindings = allFindings.filter((item) => activeStatuses.has(item.status));
  const filteredFindings = allFindings.filter((item) => {
    return (
      (severity === "all" || item.severity === severity) &&
      (page === "privacy"
        ? ["privacy", "secrets"].includes(item.category)
        : category === "all" || item.category === category) &&
      (status === "all" ||
        (status === "active" ? activeStatuses.has(item.status) : item.status === status)) &&
      `${item.title} ${item.file} ${item.rule_id} ${item.cwe} ${item.cve}`
        .toLowerCase()
        .includes(query.toLowerCase())
    );
  });
  const score = scopedReports.length
    ? Math.round(
        scopedReports.reduce((sum, report) => sum + (report.summary?.score ?? 0), 0) /
          scopedReports.length,
      )
    : null;
  const totalFiles = scopedReports.reduce((sum, report) => sum + (report.files_scanned ?? 0), 0);
  const critical = activeFindings.filter((item) => item.severity === "critical").length;
  const high = activeFindings.filter((item) => item.severity === "high").length;
  const secrets = activeFindings.filter((item) => item.category === "secrets").length;
  const lastScan = scopedScans.find((scan) => scan.status === "completed");
  const currentLabel =
    page === "settings" ? "Workspace settings" : navigation.find((item) => item.id === page)?.label;

  async function demo() {
    setBusy(true);
    setError("");
    try {
      const scan = await api<Scan>("/scans/demo", { method: "POST" });
      await created(scan);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start the sample scan.");
    } finally {
      setBusy(false);
    }
  }
  async function created(scan: Scan) {
    setScope("all");
    setToast(`${scan.repository_name} was added to the scan queue.`);
    await refresh(true);
  }
  async function logout() {
    await api("/auth/logout", { method: "POST" });
    window.location.reload();
  }

  if (session?.login_required && !session.authenticated)
    return <Login session={session} onSignedIn={() => window.location.reload()} />;

  return (
    <div className="workspace">
      {mobileNav && (
        <button
          className="sidebar-backdrop"
          aria-label="Close navigation"
          onClick={() => setMobileNav(false)}
        />
      )}
      <aside className={`sidebar ${mobileNav ? "mobile-open" : ""}`}>
        <Brand />
        <div className="workspace-switch">
          <span className="workspace-initial">SC</span>
          <div>
            <strong>Personal workspace</strong>
            <span>{settings?.auth_required ? "Owner access" : "Local access"}</span>
          </div>
          <ChevronDown size={14} />
        </div>
        <span className="nav-eyebrow">WORKSPACE</span>
        <nav aria-label="Main navigation">
          {navigation.map((item) => (
            <button
              key={item.id}
              className={page === item.id ? "active" : ""}
              onClick={() => navigate(item.id)}
              aria-current={page === item.id ? "page" : undefined}
            >
              <item.icon size={18} strokeWidth={1.6} />
              <span>{item.label}</span>
              {item.id === "findings" && activeFindings.length > 0 && (
                <small>{activeFindings.length}</small>
              )}
              {item.id === "privacy" && <span className="nav-tag">DG</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="local-card">
            <Terminal size={19} />
            <strong>Your next project, covered.</strong>
            <p>Run the same checks from any repository.</p>
            <code>sentricode scan .</code>
          </div>
          <button
            className={`settings-nav ${page === "settings" ? "active" : ""}`}
            onClick={() => navigate("settings")}
          >
            <Settings2 size={18} /> Settings & policies
          </button>
          <div className="profile">
            <span className="avatar">{session?.user?.name?.slice(0, 1) || "L"}</span>
            <div>
              <strong>{session?.user?.name || "Local developer"}</strong>
              <span>SentriCode v0.1</span>
            </div>
            {settings?.auth_required && (
              <button className="icon-button" aria-label="Sign out" onClick={logout}>
                <LogOut size={15} />
              </button>
            )}
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            <button
              className="icon-button mobile-menu"
              aria-label="Open navigation"
              onClick={() => setMobileNav(true)}
            >
              <Menu size={20} />
            </button>
            <Shield size={16} />
            <span>Workspace</span>
            <ChevronRight size={13} />
            <strong>{currentLabel}</strong>
          </div>
          <div className="topbar-actions">
            <span className="local-indicator">
              <LockKeyhole size={13} />
              {settings?.ai_configured ? "AI on request" : "Private by default"}
            </span>
            <button
              className="icon-button"
              onClick={() => navigate("settings")}
              aria-label="Privacy and workspace settings"
            >
              <BookOpen size={17} />
            </button>
          </div>
        </header>
        <main id="main-content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">
                {page === "overview" ? "SECURITY WORKSPACE" : "SENTRICODE / WORKSPACE"}
              </div>
              <h1>
                {page === "overview"
                  ? "Know what ships."
                  : page === "privacy"
                    ? "Keep sensitive data close."
                    : currentLabel}
              </h1>
              <p>
                {page === "overview"
                  ? "A clearer picture of your code. A more confident next commit."
                  : page === "findings"
                    ? "Follow the evidence, review the risk, and decide what to fix."
                    : page === "privacy"
                      ? "Review exposed credentials and sensitive data in application logs."
                      : page === "history"
                        ? "Every scan is a snapshot. See what changed between them."
                        : page === "repositories"
                          ? "Your projects and their latest security checks."
                          : page === "dependencies"
                            ? "The packages your projects rely on, with versions from their manifests."
                            : "Privacy, quality gates, and a record of your decisions."}
              </p>
            </div>
            <button className="button primary new-scan-button" onClick={() => setNewScan(true)}>
              <Plus size={17} /> New scan
            </button>
          </div>
          {error && (
            <ErrorNotice>
              {error}
              <button className="text-button" onClick={() => void refresh()}>
                Try again
              </button>
            </ErrorNotice>
          )}
          {running.length > 0 && (
            <div className="running-banner" role="status">
              <LoaderCircle className="spin" size={17} />
              <div>
                <strong>
                  {running.length === 1 ? running[0].repository_name : `${running.length} projects`}
                </strong>
                <span>
                  {humanize(running[0].stage || running[0].status)} · this page updates
                  automatically
                </span>
              </div>
              <button className="text-button" onClick={() => navigate("history")}>
                View scans <ArrowRight size={14} />
              </button>
            </div>
          )}
          <div className="scope-bar">
            <RepositoryPicker
              value={scope}
              onChange={setScope}
              repositories={repositories}
              reports={reports}
            />
            <div className="scope-meta">
              <span>
                {lastScan ? `Last scan ${date(lastScan.completed_at)}` : "No completed scans yet"}
              </span>
              <button
                className="icon-button"
                aria-label="Refresh workspace"
                onClick={() => void refresh(true)}
              >
                <RefreshCw size={15} className={loading ? "spin" : ""} />
              </button>
            </div>
          </div>
          {loading && !scans.length ? (
            <div className="initial-loading">
              <LoaderCircle className="spin" size={24} />
              <p>Opening your workspace…</p>
            </div>
          ) : (
            <>
              {page === "overview" && (
                <>
                  <div className="stat-grid">
                    <div className="stat-card posture">
                      <span className="stat-label">
                        <ShieldCheck size={16} />
                        Security posture{" "}
                        <span title="Average latest scan score per repository. A prioritization heuristic, not proof that a project is secure.">
                          <CircleHelp size={13} />
                        </span>
                      </span>
                      <div className="stat-value">
                        {score ?? "—"}
                        <span>/ 100</span>
                      </div>
                      <div className="score-track">
                        <span style={{ width: `${score ?? 0}%` }} />
                      </div>
                      <span className="stat-foot">
                        {score == null
                          ? "Your first scan starts here"
                          : "Average of latest scan scores"}
                      </span>
                    </div>
                    <Stat
                      label="Needs attention"
                      value={activeFindings.length}
                      detail={`${critical} critical · ${high} high severity`}
                      icon={Shield}
                      tone="orange"
                    />
                    <Stat
                      label="Exposed secrets"
                      value={secrets}
                      detail="Active findings to review"
                      icon={LockKeyhole}
                      tone="rose"
                    />
                    <Stat
                      label="Projects scanned"
                      value={scopedReports.length}
                      detail={`${totalFiles.toLocaleString()} files checked in latest scans`}
                      icon={FolderGit2}
                      tone="blue"
                    />
                  </div>
                  {!scopedReports.length ? (
                    <div className="onboarding-grid">
                      <section className="panel welcome-panel">
                        <span className="eyebrow">YOUR FIRST CHECK</span>
                        <h2>
                          Good code deserves
                          <br /> a second look.
                        </h2>
                        <p>
                          Bring a project. SentriCode checks for unsafe patterns, exposed secrets,
                          and confidentiality risks, then keeps the evidence in one place.
                        </p>
                        <div className="button-row">
                          <button className="button primary" onClick={() => setNewScan(true)}>
                            <Plus size={16} />
                            Scan a project
                          </button>
                          <button className="button secondary" onClick={demo} disabled={busy}>
                            {busy ? (
                              <LoaderCircle size={16} className="spin" />
                            ) : (
                              <Code2 size={16} />
                            )}
                            Try a sample
                          </button>
                        </div>
                        <span className="field-hint">
                          The sample contains deliberately vulnerable code and is never executed.
                        </span>
                      </section>
                      <section className="panel checklist-panel">
                        <div className="panel-heading">
                          <h2>Inside each scan</h2>
                          <span className="subtle-tag">LOCAL FIRST</span>
                        </div>
                        {categories.map((item) => (
                          <div className="checklist-item" key={item.id}>
                            <span className="category-icon">
                              <item.icon size={18} />
                            </span>
                            <div>
                              <strong>{item.title}</strong>
                              <span>
                                {item.id === "sast"
                                  ? "Unsafe code patterns and APIs"
                                  : item.id === "secrets"
                                    ? "Credentials that should stay private"
                                    : item.id === "dependencies"
                                      ? "Package inventory and optional OSV lookup"
                                      : item.id === "iac"
                                        ? "Common configuration risks"
                                        : "Sensitive values reaching logs"}
                              </span>
                            </div>
                            <Check size={15} />
                          </div>
                        ))}
                      </section>
                    </div>
                  ) : (
                    <>
                      <div className="overview-mid">
                        <section className="panel category-panel">
                          <div className="panel-heading">
                            <h2>Where to focus</h2>
                            <span className="muted">{activeFindings.length} active</span>
                          </div>
                          {categories.map((item) => {
                            const count = activeFindings.filter(
                              (f) => f.category === item.id,
                            ).length;
                            return (
                              <button
                                key={item.id}
                                className="category-row"
                                onClick={() => {
                                  setCategory(item.id);
                                  setStatus("active");
                                  navigate(item.id === "privacy" ? "privacy" : "findings");
                                }}
                              >
                                <item.icon size={17} />
                                <span>{item.title}</span>
                                <div className="category-bar">
                                  <span
                                    style={{
                                      width: `${Math.max(0, (count / Math.max(1, activeFindings.length)) * 100)}%`,
                                    }}
                                  />
                                </div>
                                <strong>{count}</strong>
                                <ChevronRight size={14} />
                              </button>
                            );
                          })}
                        </section>
                        <section className="panel trend-panel">
                          <div className="panel-heading">
                            <h2>Security posture over time</h2>
                            <span className="subtle-tag">SCAN SCORES</span>
                          </div>
                          <Trend scans={scopedScans} />
                          <p className="field-hint">
                            {scope === "all"
                              ? "Completed scans across this workspace. Select one repository for a comparable trend."
                              : "Latest completed scans for this repository. Higher scores mean fewer weighted findings."}
                          </p>
                        </section>
                      </div>
                      <section className="panel priority-panel">
                        <div className="panel-heading">
                          <div>
                            <h2>Start with these findings</h2>
                            <p>Active findings, ordered by SentriScore.</p>
                          </div>
                          <button
                            className="text-button"
                            onClick={() => {
                              setCategory("all");
                              navigate("findings");
                            }}
                          >
                            View all findings <ArrowUpRight size={15} />
                          </button>
                        </div>
                        <FindingTable findings={activeFindings} onSelect={setFinding} limit={5} />
                      </section>
                    </>
                  )}
                  <section className="panel recent-panel">
                    <div className="panel-heading">
                      <h2>Recent activity</h2>
                      <button className="text-button" onClick={() => navigate("history")}>
                        Scan history <ArrowRight size={15} />
                      </button>
                    </div>
                    {!scopedScans.length ? (
                      <p className="no-activity">
                        Scan activity will appear here when you add a project.
                      </p>
                    ) : (
                      scopedScans.slice(0, 3).map((scan) => (
                        <div className="recent-row" key={scan.id}>
                          <span className="repo-icon">
                            <FolderGit2 size={18} />
                          </span>
                          <div className="recent-name">
                            <strong>{scan.repository_name}</strong>
                            <span>
                              {scan.mode} scan · {date(scan.created_at)}
                            </span>
                          </div>
                          <Status status={scan.status} />
                          <span className="recent-count">
                            {scan.summary
                              ? `${scan.summary.total} findings`
                              : scan.stage || "Preparing"}
                          </span>
                          <button
                            className="icon-button"
                            aria-label={`Review scan for ${scan.repository_name}`}
                            onClick={() => {
                              setScope(scan.repository_id);
                              navigate("history");
                            }}
                          >
                            <ArrowUpRight size={17} />
                          </button>
                        </div>
                      ))
                    )}
                  </section>
                </>
              )}
              {page === "repositories" &&
                (repositories.length ? (
                  <div className="repository-grid">
                    {repositories
                      .filter((repo) => scope === "all" || repo.id === scope)
                      .map((repo) => {
                        const report = reports.find((item) => item.repository_id === repo.id);
                        return (
                          <section key={repo.id} className="panel repository-card">
                            <div className="repository-card-heading">
                              <span className="repo-icon large">
                                <FolderGit2 size={23} />
                              </span>
                              <span className="subtle-tag">{repo.source}</span>
                            </div>
                            <h2>{repo.name}</h2>
                            <p>{repo.url || "Uploaded source archive"}</p>
                            <div className="repository-stats">
                              <div>
                                <strong>
                                  {report?.summary?.score ?? "—"}
                                  <small>/100</small>
                                </strong>
                                <span>Scan posture</span>
                              </div>
                              <div>
                                <strong>{report?.summary?.total ?? "—"}</strong>
                                <span>Findings</span>
                              </div>
                              <div>
                                <strong>{repo.scan_count}</strong>
                                <span>Scans</span>
                              </div>
                            </div>
                            <div className="repository-footer">
                              <span>{date(report?.completed_at)}</span>
                              <button
                                className="text-button"
                                onClick={() => {
                                  setScope(repo.id);
                                  setCategory("all");
                                  navigate("findings");
                                }}
                              >
                                Review project <ArrowUpRight size={15} />
                              </button>
                            </div>
                          </section>
                        );
                      })}
                  </div>
                ) : (
                  <Empty
                    title="A home for your projects"
                    action={
                      <button className="button primary" onClick={() => setNewScan(true)}>
                        <Plus size={16} />
                        Add your first project
                      </button>
                    }
                  >
                    Upload a source archive or import a GitHub repository to begin.
                  </Empty>
                ))}
              {["findings", "privacy"].includes(page) && (
                <>
                  {page === "privacy" && (
                    <div className="info-banner">
                      <LockKeyhole size={19} />
                      <div>
                        <strong>Confidentiality, with evidence.</strong>
                        <p>
                          DataGuard highlights possible sensitive logging. Secret detection finds
                          credential patterns. Review context before deciding whether a finding is
                          actionable.
                        </p>
                      </div>
                    </div>
                  )}
                  <div className="filter-toolbar">
                    <label className="search-field">
                      <Search size={16} />
                      <input
                        value={query}
                        onChange={(event) => setQuery(event.target.value)}
                        placeholder="Search title, file, or CWE…"
                        aria-label="Search findings"
                      />
                    </label>
                    <select
                      aria-label="Severity"
                      value={severity}
                      onChange={(event) => setSeverity(event.target.value)}
                    >
                      <option value="all">All severities</option>
                      {["critical", "high", "medium", "low", "info"].map((item) => (
                        <option key={item} value={item}>
                          {humanize(item)}
                        </option>
                      ))}
                    </select>
                    {page !== "privacy" && (
                      <select
                        aria-label="Finding category"
                        value={category}
                        onChange={(event) => setCategory(event.target.value)}
                      >
                        <option value="all">All categories</option>
                        {categories.map((item) => (
                          <option key={item.id} value={item.id}>
                            {item.title}
                          </option>
                        ))}
                      </select>
                    )}
                    <select
                      aria-label="Finding status"
                      value={status}
                      onChange={(event) => setStatus(event.target.value)}
                    >
                      <option value="active">Active findings</option>
                      <option value="all">All statuses</option>
                      {["resolved", "accepted_risk", "false_positive"].map((item) => (
                        <option key={item} value={item}>
                          {humanize(item)}
                        </option>
                      ))}
                    </select>
                  </div>
                  <section className="panel">
                    <div className="panel-heading">
                      <h2>
                        {page === "privacy" ? "Secrets & confidentiality" : "Findings"}{" "}
                        <span className="count-chip">{filteredFindings.length}</span>
                      </h2>
                      <span className="muted">Latest completed scan per project</span>
                    </div>
                    <FindingTable findings={filteredFindings} onSelect={setFinding} />
                  </section>
                </>
              )}
              {page === "dependencies" && (
                <DependenciesPanel
                  reports={scopedReports}
                  findings={allFindings}
                  onSelect={setFinding}
                />
              )}
              {page === "history" && (
                <HistoryPanel
                  scans={scopedScans}
                  onSelect={setFinding}
                  onChange={() => void refresh(true)}
                  notify={setToast}
                />
              )}
              {page === "settings" && (
                <SettingsPanel
                  settings={settings}
                  audit={audit}
                  onChange={() => void refresh(true)}
                  notify={setToast}
                />
              )}
            </>
          )}
          <footer className="workspace-footer">
            <span>
              <Shield size={13} /> Built to check. Designed to question.
            </span>
            <span>Deterministic findings. Human decisions.</span>
          </footer>
        </main>
      </div>
      <NewScan
        open={newScan}
        onOpenChange={setNewScan}
        onCreated={(scan) => void created(scan)}
        settings={settings}
      />
      {finding && (
        <FindingDetail
          key={finding.id}
          finding={finding}
          onClose={() => setFinding(undefined)}
          onChange={() => void refresh(true)}
          settings={settings}
        />
      )}
      {toast && (
        <div className="toast" role="status">
          <Check size={17} />
          {toast}
          <button
            className="icon-button"
            aria-label="Dismiss notification"
            onClick={() => setToast("")}
          >
            <X size={15} />
          </button>
        </div>
      )}
    </div>
  );
}

function Stat({
  label,
  value,
  detail,
  icon: Icon,
  tone,
}: {
  label: string;
  value: number;
  detail: string;
  icon: typeof Shield;
  tone: string;
}) {
  return (
    <div className={`stat-card ${tone}`}>
      <span className="stat-label">
        <Icon size={16} />
        {label}
      </span>
      <div className="stat-value">{value}</div>
      <span className="stat-foot">{detail}</span>
    </div>
  );
}

function Trend({ scans }: { scans: Scan[] }) {
  const completed = scans
    .filter((scan) => scan.status === "completed" && scan.summary)
    .slice(0, 9)
    .reverse();
  if (completed.length < 2)
    return (
      <div className="trend-empty">
        <Activity size={25} />
        <strong>A trend takes a second scan.</strong>
        <span>Run another scan to compare your security posture.</span>
      </div>
    );
  const values = completed.map((scan, index) => ({
    x: 20 + (index / (completed.length - 1)) * 510,
    y: 124 - (scan.summary?.score ?? 0) * 1.03,
    score: scan.summary?.score,
    id: scan.id,
    date: date(scan.completed_at, true),
  }));
  const points = values.map((item) => `${item.x},${item.y}`).join(" ");
  return (
    <div className="trend">
      <svg
        viewBox="0 0 550 158"
        role="img"
        aria-label={`Scan scores: ${values.map((item) => `${item.date}: ${item.score}`).join(", ")}`}
      >
        <defs>
          <linearGradient id="trend-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#8fe7bd" stopOpacity="0.18" />
            <stop offset="100%" stopColor="#8fe7bd" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[25, 75, 125].map((y) => (
          <line key={y} x1="20" x2="530" y1={y} y2={y} stroke="#273238" strokeDasharray="4 6" />
        ))}
        <polygon points={`20,128 ${points} 530,128`} fill="url(#trend-fill)" />
        <polyline
          className="trend-line"
          points={points}
          fill="none"
          stroke="#8fe7bd"
          strokeWidth="2.5"
          strokeLinejoin="round"
        />
        {values.map((item, index) => (
          <g
            className="trend-marker"
            key={item.id}
            style={{ "--point-index": index } as CSSProperties}
          >
            <circle cx={item.x} cy={item.y} r="4" fill="#8fe7bd" stroke="#131e25" strokeWidth="2" />
            <title>
              {item.date}: {item.score}/100
            </title>
          </g>
        ))}
        <text x="20" y="151" fill="#8d9ca5" fontSize="12">
          {values[0].date}
        </text>
        <text x="530" y="151" fill="#8d9ca5" fontSize="12" textAnchor="end">
          {values[values.length - 1].date}
        </text>
      </svg>
    </div>
  );
}

function Login({ session, onSignedIn }: { session: Session; onSignedIn: () => void }) {
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      await api("/auth/login", { method: "POST", body: JSON.stringify({ token }) });
      onSignedIn();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="login-page">
      <section className="login-card">
        <Brand />
        <span className="eyebrow">YOUR PRIVATE WORKSPACE</span>
        <h1>Welcome back.</h1>
        <p>Sign in to review your projects and security findings.</p>
        <form onSubmit={submit}>
          <label className="field">
            Workspace access token
            <input
              type="password"
              value={token}
              onChange={(event) => setToken(event.target.value)}
              autoComplete="current-password"
              required
            />
          </label>
          {error && <ErrorNotice>{error}</ErrorNotice>}
          <button className="button primary" disabled={busy}>
            {busy ? <LoaderCircle size={16} className="spin" /> : <LockKeyhole size={16} />}Open
            workspace
          </button>
        </form>
        {session.github_configured && (
          <a className="button secondary" href="/api/v1/auth/github/start">
            <GitFork size={17} />
            Sign in with GitHub
          </a>
        )}
        <p className="field-hint">Use the SENTRICODE_TOKEN set by the workspace owner.</p>
      </section>
    </main>
  );
}
