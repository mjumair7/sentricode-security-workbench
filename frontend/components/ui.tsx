"use client";

import * as Dialog from "@radix-ui/react-dialog";
import { X, ChevronRight, Shield, LoaderCircle } from "lucide-react";
import type { ReactNode } from "react";
import type { Finding, Severity } from "@/lib/types";
import { humanize } from "@/lib/api";

export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className="brand">
      <span className="brand-mark">
        <Shield size={23} strokeWidth={1.8} />
      </span>
      {!compact && (
        <span>
          Sentri<span className="brand-light">Code</span>
          <sup> / 01</sup>
        </span>
      )}
    </div>
  );
}

export function Badge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge ${severity}`}>
      <span />
      {severity}
    </span>
  );
}

export function Status({ status }: { status: string }) {
  return (
    <span className={`status ${status}`}>
      {["running", "queued"].includes(status) && <LoaderCircle size={12} className="spin" />}
      {humanize(status)}
    </span>
  );
}

export function Modal({
  open,
  onOpenChange,
  title,
  description,
  children,
  wide = false,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  children: ReactNode;
  wide?: boolean;
}) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="modal-overlay" />
        <Dialog.Content
          className={`modal ${wide ? "wide" : ""}`}
          {...(!description ? { "aria-describedby": undefined } : {})}
        >
          <div className="modal-heading">
            <div>
              <Dialog.Title>{title}</Dialog.Title>
              {description && <Dialog.Description>{description}</Dialog.Description>}
            </div>
            <Dialog.Close className="icon-button" aria-label="Close dialog">
              <X size={20} />
            </Dialog.Close>
          </div>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export function FindingTable({
  findings,
  onSelect,
  limit,
}: {
  findings: Finding[];
  onSelect: (finding: Finding) => void;
  limit?: number;
}) {
  if (!findings.length)
    return (
      <div className="empty-inline">
        <Shield size={26} />
        <h3>No findings in this view</h3>
        <p>Try another filter or run a scan to collect evidence.</p>
      </div>
    );
  return (
    <div className="table-scroll">
      <table className="finding-table">
        <thead>
          <tr>
            <th>Finding / location</th>
            <th>Severity</th>
            <th>Source</th>
            <th>Risk</th>
            <th>
              <span className="sr-only">Open finding</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {findings.slice(0, limit ?? findings.length).map((finding) => (
            <tr key={finding.id}>
              <td>
                <button className="finding-title" onClick={() => onSelect(finding)}>
                  {finding.title}
                </button>
                <span className="file-label">
                  {finding.file}
                  {finding.line_start ? `:${finding.line_start}` : ""}
                </span>
              </td>
              <td>
                <Badge severity={finding.severity} />
              </td>
              <td>
                <span className="source-label">{finding.scanner}</span>
                <span className="file-label">{finding.cwe || humanize(finding.category)}</span>
              </td>
              <td>
                <span className={`risk-value risk-${finding.severity}`}>
                  {finding.sentri_score}
                </span>
                <span className="muted"> / 100</span>
              </td>
              <td>
                <button
                  className="icon-button"
                  aria-label={`View ${finding.title}`}
                  onClick={() => onSelect(finding)}
                >
                  <ChevronRight size={17} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Empty({
  title,
  children,
  action,
}: {
  title: string;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <div className="empty-symbol">
        <Shield size={32} strokeWidth={1.5} />
      </div>
      <h2>{title}</h2>
      <p>{children}</p>
      {action}
    </div>
  );
}

export function ErrorNotice({ children }: { children: ReactNode }) {
  return (
    <div className="error-notice" role="alert">
      {children}
    </div>
  );
}
