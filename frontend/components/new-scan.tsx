"use client";

import { useRef, useState } from "react";
import {
  Archive,
  ArrowUpRight,
  Check,
  FileArchive,
  FolderGit2,
  GitFork,
  LoaderCircle,
  LockKeyhole,
  Upload,
} from "lucide-react";
import { api } from "@/lib/api";
import type { Scan, Settings } from "@/lib/types";
import { ErrorNotice, Modal } from "./ui";

export function NewScan({
  open,
  onOpenChange,
  onCreated,
  settings,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (scan: Scan) => void;
  settings?: Settings;
}) {
  const [source, setSource] = useState("upload");
  const [file, setFile] = useState<File>();
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [ref, setRef] = useState("");
  const [mode, setMode] = useState("standard");
  const [network, setNetwork] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);

  function selectFile(selected?: File) {
    if (!selected) return;
    if (!selected.name.toLowerCase().endsWith(".zip")) {
      setError("Choose a ZIP archive of your source code.");
      return;
    }
    if (selected.size > 25 * 1024 * 1024) {
      setError("The archive must be 25 MB or smaller. Leave out dependencies and build outputs.");
      return;
    }
    setFile(selected);
    setError("");
    if (!name) setName(selected.name.replace(/\.zip$/i, ""));
  }
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      let scan: Scan;
      if (source === "upload") {
        if (!file) throw new Error("Choose a ZIP archive first.");
        const form = new FormData();
        form.set("file", file);
        form.set("name", name || file.name.replace(/\.zip$/i, ""));
        form.set("mode", mode);
        form.set("network", String(network));
        scan = await api<Scan>("/scans/upload", { method: "POST", body: form });
      } else {
        scan = await api<Scan>("/scans/github", {
          method: "POST",
          body: JSON.stringify({ url, ref: ref || undefined, mode, network }),
        });
      }
      onCreated(scan);
      onOpenChange(false);
      setFile(undefined);
      setUrl("");
      setName("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "The scan could not be started.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={open}
      onOpenChange={(value) => {
        if (!busy) onOpenChange(value);
      }}
      title="Start a security scan"
      description="Choose a project. Your code is inspected without running it."
    >
      <form onSubmit={submit}>
        <div className="segmented" aria-label="Repository source">
          <button
            type="button"
            className={source === "upload" ? "active" : ""}
            onClick={() => setSource("upload")}
          >
            <Archive size={16} /> Upload ZIP
          </button>
          <button
            type="button"
            className={source === "github" ? "active" : ""}
            onClick={() => setSource("github")}
          >
            <GitFork size={16} /> GitHub repository
          </button>
        </div>
        {source === "upload" ? (
          <>
            <input
              ref={fileInput}
              type="file"
              accept=".zip,application/zip"
              className="sr-only"
              aria-label="Source archive"
              onChange={(event) => selectFile(event.target.files?.[0])}
            />
            <button
              type="button"
              className={`dropzone ${file ? "selected" : ""}`}
              onClick={() => fileInput.current?.click()}
              onDragOver={(event) => event.preventDefault()}
              onDrop={(event) => {
                event.preventDefault();
                selectFile(event.dataTransfer.files[0]);
              }}
            >
              {file ? <FileArchive size={30} /> : <Upload size={30} />}
              <strong>{file ? file.name : "Drop your repository here"}</strong>
              <span>
                {file
                  ? `${(file.size / 1024).toFixed(0)} KB · click to replace`
                  : "or choose a ZIP file · up to 25 MB"}
              </span>
            </button>
            <label className="field">
              Project name
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                maxLength={120}
                placeholder="my-next-project"
                required
              />
            </label>
          </>
        ) : (
          <div className="form-stack">
            <label className="field">
              Repository URL
              <input
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                type="url"
                placeholder="https://github.com/you/your-project"
                required
              />
            </label>
            <label className="field">
              Branch, tag, or commit <span className="muted">(optional)</span>
              <input
                value={ref}
                onChange={(event) => setRef(event.target.value)}
                placeholder="Repository default branch"
                maxLength={200}
              />
            </label>
            <p className="field-hint">
              Public repositories work immediately. For private repositories, configure a GitHub
              token on the server.
            </p>
          </div>
        )}
        <fieldset className="scan-modes">
          <legend>Scan depth</legend>
          {[
            { id: "quick", title: "Quick", text: "Code, secrets & privacy" },
            { id: "standard", title: "Standard", text: "Add dependencies & config" },
            { id: "deep", title: "Deep", text: "Standard + coverage notes" },
          ].map((item) => (
            <label key={item.id} className={mode === item.id ? "selected" : ""}>
              <input
                type="radio"
                name="mode"
                value={item.id}
                checked={mode === item.id}
                onChange={() => setMode(item.id)}
              />
              <strong>
                {item.title}
                {mode === item.id && <Check size={13} />}
              </strong>
              <span>{item.text}</span>
            </label>
          ))}
        </fieldset>
        <label className="check-row">
          <input
            type="checkbox"
            checked={network}
            onChange={(event) => setNetwork(event.target.checked)}
            disabled={!settings?.network_enabled}
          />
          <span>
            <strong>Look up known dependency vulnerabilities</strong>
            <small>
              {settings?.network_enabled
                ? "Sends package names and versions to OSV, and CVE IDs to public threat feeds."
                : "Enable SENTRICODE_NETWORK_ENABLED on the server to use public threat feeds."}
            </small>
          </span>
        </label>
        <div className="privacy-note">
          <LockKeyhole size={15} />
          <span>AI is off during scans. Source files are deleted after analysis.</span>
        </div>
        {error && <ErrorNotice>{error}</ErrorNotice>}
        <div className="modal-footer">
          <button
            className="button secondary"
            type="button"
            disabled={busy}
            onClick={() => onOpenChange(false)}
          >
            Cancel
          </button>
          <button className="button primary" disabled={busy || (source === "upload" && !file)}>
            {busy ? <LoaderCircle className="spin" size={16} /> : <FolderGit2 size={16} />}
            {busy ? "Preparing scan…" : "Start scan"}
            {!busy && <ArrowUpRight size={16} />}
          </button>
        </div>
      </form>
    </Modal>
  );
}
