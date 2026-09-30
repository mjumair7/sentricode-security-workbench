"use client";

import { useEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { Check, ChevronDown, FolderGit2, LayoutGrid, ShieldCheck } from "lucide-react";
import { date, humanize } from "@/lib/api";
import type { Repository, Scan } from "@/lib/types";

type RepositoryPickerProps = {
  value: string;
  onChange: (value: string) => void;
  repositories: Repository[];
  reports: Scan[];
};

function findingsLabel(count: number) {
  return `${count} ${count === 1 ? "finding" : "findings"}`;
}

export function RepositoryPicker({
  value,
  onChange,
  repositories,
  reports,
}: RepositoryPickerProps) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const optionRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const selected = repositories.find((repository) => repository.id === value);
  const selectedReport = reports.find((report) => report.repository_id === value);
  const totalFindings = reports.reduce((total, report) => total + (report.summary?.total ?? 0), 0);
  const averageScore = reports.length
    ? Math.round(
        reports.reduce((total, report) => total + (report.summary?.score ?? 0), 0) / reports.length,
      )
    : null;

  useEffect(() => {
    if (!open) return;
    const close = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    };
    const escape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
        trigger.current?.focus();
      }
    };
    document.addEventListener("pointerdown", close);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("pointerdown", close);
      document.removeEventListener("keydown", escape);
    };
  }, [open]);

  function choose(next: string) {
    onChange(next);
    setOpen(false);
    trigger.current?.focus();
  }

  function moveFocus(event: ReactKeyboardEvent, index: number) {
    if (!open || (event.key !== "ArrowDown" && event.key !== "ArrowUp")) return;
    event.preventDefault();
    const total = repositories.length + 1;
    const next = event.key === "ArrowDown" ? (index + 1) % total : (index - 1 + total) % total;
    optionRefs.current[next]?.focus();
  }

  return (
    <div className="repository-picker" ref={root}>
      <button
        ref={trigger}
        type="button"
        className="repository-trigger"
        aria-label="Filter by repository"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls="repository-scope-list"
        onClick={() => setOpen((current) => !current)}
        onKeyDown={(event) => {
          if (event.key === "ArrowDown") {
            event.preventDefault();
            setOpen(true);
            const selectedIndex =
              value === "all"
                ? 0
                : Math.max(0, repositories.findIndex((repository) => repository.id === value) + 1);
            requestAnimationFrame(() => optionRefs.current[selectedIndex]?.focus());
          }
        }}
      >
        <span className="repository-trigger-icon">
          {value === "all" ? <LayoutGrid size={16} /> : <FolderGit2 size={16} />}
        </span>
        <span className="repository-trigger-copy">
          <strong>{selected?.name || "All repositories"}</strong>
          <small>
            {selected
              ? `${findingsLabel(selectedReport?.summary?.total ?? 0)} · ${selected.source}`
              : `${repositories.length} ${repositories.length === 1 ? "project" : "projects"} · ${findingsLabel(totalFindings)}`}
          </small>
        </span>
        <span className="repository-trigger-score">
          {value === "all" ? (averageScore ?? "—") : (selectedReport?.summary?.score ?? "—")}
          <small>/100</small>
        </span>
        <ChevronDown className="repository-chevron" size={15} />
      </button>

      {open && (
        <div
          id="repository-scope-list"
          className="repository-menu"
          role="listbox"
          aria-label="Repository scope"
        >
          <div className="repository-menu-heading">
            <div>
              <span>REPOSITORY SCOPE</span>
              <strong>Choose what the workspace summarizes</strong>
            </div>
            <kbd>esc</kbd>
          </div>
          <button
            ref={(node) => {
              optionRefs.current[0] = node;
            }}
            className={`repository-option ${value === "all" ? "selected" : ""}`}
            type="button"
            role="option"
            aria-selected={value === "all"}
            onClick={() => choose("all")}
            onKeyDown={(event) => moveFocus(event, 0)}
          >
            <span className="repository-option-icon all">
              <LayoutGrid size={17} />
            </span>
            <span className="repository-option-copy">
              <strong>All repositories</strong>
              <small>{repositories.length} projects · latest completed scans</small>
            </span>
            <span className="repository-option-metric">
              <strong>{averageScore ?? "—"}</strong>
              <small>avg score</small>
            </span>
            <span className="repository-option-check">
              {value === "all" && <Check size={14} />}
            </span>
          </button>
          <div className="repository-menu-rule">
            <span>PROJECTS</span>
            <span>{repositories.length.toString().padStart(2, "0")}</span>
          </div>
          <div className="repository-option-list">
            {repositories.map((repository, index) => {
              const report = reports.find((item) => item.repository_id === repository.id);
              const scan = repository.latest_scan;
              return (
                <button
                  key={repository.id}
                  ref={(node) => {
                    optionRefs.current[index + 1] = node;
                  }}
                  className={`repository-option ${value === repository.id ? "selected" : ""}`}
                  type="button"
                  role="option"
                  aria-selected={value === repository.id}
                  onClick={() => choose(repository.id)}
                  onKeyDown={(event) => moveFocus(event, index + 1)}
                >
                  <span className="repository-option-icon">
                    <FolderGit2 size={17} />
                  </span>
                  <span className="repository-option-copy">
                    <strong>{repository.name}</strong>
                    <small>
                      {scan
                        ? `${humanize(scan.status)} · ${date(scan.completed_at || scan.created_at)}`
                        : "Not scanned yet"}
                    </small>
                  </span>
                  <span className="repository-option-metric">
                    <strong>{report?.summary?.score ?? "—"}</strong>
                    <small>{findingsLabel(report?.summary?.total ?? 0)}</small>
                  </span>
                  <span className="repository-option-check">
                    {value === repository.id ? <Check size={14} /> : <ShieldCheck size={14} />}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
