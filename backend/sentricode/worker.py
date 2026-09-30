"""Durable database queue; run in-process locally or as a separate service."""
from datetime import timedelta
import logging
import shutil
import signal
import threading
import time
from sqlalchemy import select, update
from .config import Settings
from .db import Database
from .ingestion import IngestionError, download_github, extract_zip, write_demo
from .models import Audit, Finding, Scan, uid, utcnow

log = logging.getLogger(__name__)


def clean_job(settings: Settings, scan_id: str):
    if len(scan_id) == 32 and all(char in "0123456789abcdef" for char in scan_id):
        shutil.rmtree(settings.jobs_dir / scan_id, ignore_errors=True)


def claim_job(database: Database) -> tuple[str, str] | None:
    with database.session() as session:
        # A dead worker leaves a lease behind. Retrying is safe: scanners only read source.
        cutoff = utcnow() - timedelta(minutes=5)
        session.execute(update(Scan).where(Scan.status == "running", Scan.heartbeat_at < cutoff).values(status="queued", stage="recovered after worker interruption"))
        session.commit()
        scan_id = session.scalar(select(Scan.id).where(Scan.status == "queued").order_by(Scan.created_at).limit(1))
        if not scan_id:
            return None
        lease = uid()
        claimed = session.execute(update(Scan).where(Scan.id == scan_id, Scan.status == "queued").values(status="running", stage="preparing source", started_at=utcnow(), heartbeat_at=utcnow(), lease_id=lease))
        session.commit()
        return (scan_id, lease) if claimed.rowcount else None


def process_job(database: Database, settings: Settings, scan_id: str, lease: str):
    done = threading.Event()

    def heartbeat():
        while not done.wait(20):
            try:
                with database.session() as session:
                    session.execute(update(Scan).where(Scan.id == scan_id, Scan.status == "running", Scan.lease_id == lease).values(heartbeat_at=utcnow()))
                    session.commit()
            except Exception as exc:
                log.warning("Heartbeat unavailable (%s)", type(exc).__name__)

    pulse = threading.Thread(target=heartbeat, daemon=True, name=f"scan-heartbeat-{scan_id[:8]}")
    pulse.start()
    job = settings.jobs_dir / scan_id

    def progress(stage: str, message: str = ""):
        with database.session() as session:
            session.execute(update(Scan).where(Scan.id == scan_id, Scan.lease_id == lease).values(stage=str(stage)[:80], heartbeat_at=utcnow()))
            session.commit()

    try:
        with database.session() as session:
            scan = session.get(Scan, scan_id)
            if not scan or scan.lease_id != lease or scan.status != "running":
                return
            options = scan.options
            mode = scan.mode
        job.mkdir(parents=True, exist_ok=True, mode=0o700)
        source_kind = options.get("source", "upload")
        if source_kind == "github":
            progress("downloading repository")
            archive = job / "repository.zip"
            archive.unlink(missing_ok=True)
            download_github(options["url"], options.get("ref"), archive, settings)
            shutil.rmtree(job / "source", ignore_errors=True)
            root = extract_zip(archive, job / "source", settings)
            archive.unlink(missing_ok=True)
        elif source_kind == "demo":
            root = write_demo(job / "source")
        else:
            root = (job / options.get("root", "source")).resolve()
            if not root.is_relative_to(job.resolve()) or not root.is_dir():
                raise IngestionError("The queued upload is no longer available; upload it again")
        from .scanner import scan_directory
        report = scan_directory(root, mode=mode, network=bool(options.get("network") and settings.network_enabled), external=False, history=False, progress=progress)
        raw_findings = report.pop("findings", [])
        if source_kind == "demo":
            report.setdefault("warnings", []).insert(0, "Intentionally vulnerable demo source. These findings are examples, not a scan of your own project.")
        with database.session() as session:
            scan = session.get(Scan, scan_id)
            if not scan or scan.lease_id != lease or scan.status != "running":
                return
            for finding in raw_findings:
                fingerprint = finding.get("fingerprint") or finding.get("id")
                previous = session.scalar(select(Finding).where(Finding.repository_id == scan.repository_id, Finding.fingerprint == fingerprint).order_by(Finding.updated_at.desc()).limit(1))
                finding["first_seen"] = previous.data.get("first_seen", previous.created_at.isoformat()) if previous else utcnow().isoformat()
                finding["last_seen"] = utcnow().isoformat()
                status = previous.status if previous and previous.status != "resolved" else "open"
                finding.pop("id", None)
                finding["status"] = status
                session.add(Finding(scan_id=scan_id, repository_id=scan.repository_id, fingerprint=fingerprint, status=status, reason=previous.reason if previous else "", data=finding))
            from .cli import evaluate_policy
            policy = options.get("policy", {"fail_on": ["critical", "high"], "max_high": 0, "fail_on_secrets": True})
            result = evaluate_policy(raw_findings, policy)
            result["config"] = policy
            result["coverage_complete"] = not any(engine.get("status") == "failed" for engine in report.get("engines", []))
            if not result["coverage_complete"]:
                result["passed"] = False
                result["violations"].append("One or more enabled engines failed; coverage is incomplete.")
            report["policy"] = result
            scan.report = report
            scan.status = "completed"
            scan.stage = "completed"
            scan.completed_at = utcnow()
            session.add(Audit(action="scan.completed", resource=scan_id, detail={"findings": len(raw_findings), "files": report.get("files_scanned", 0)}))
            session.commit()
    except Exception as exc:
        error = str(exc)[:500] if isinstance(exc, IngestionError) else "The scan failed. Check worker logs, then try a smaller archive or resubmit the job."
        log.warning("Scan %s failed (%s)", scan_id, type(exc).__name__)
        with database.session() as session:
            scan = session.get(Scan, scan_id)
            if scan and scan.lease_id == lease:
                scan.status = "failed"
                scan.stage = "failed"
                scan.error = error
                scan.completed_at = utcnow()
                session.add(Audit(action="scan.failed", resource=scan_id, detail={"error": error}))
                session.commit()
    finally:
        done.set()
        pulse.join(timeout=1)
        with database.session() as session:
            current = session.get(Scan, scan_id)
            if not current or current.lease_id == lease:
                clean_job(settings, scan_id)


def clean_abandoned_sources(database: Database, settings: Settings):
    with database.session() as session:
        active = set(session.scalars(select(Scan.id).where(Scan.status.in_(["queued", "running"]))))
    for path in settings.jobs_dir.iterdir():
        if path.name not in active and path.is_dir() and time.time() - path.stat().st_mtime > 600:
            clean_job(settings, path.name)


def run_worker(database: Database, settings: Settings, stop: threading.Event):
    last_cleanup = 0.0
    while not stop.is_set():
        try:
            if time.monotonic() - last_cleanup > 60:
                clean_abandoned_sources(database, settings)
                last_cleanup = time.monotonic()
            claimed = claim_job(database)
            if claimed:
                process_job(database, settings, *claimed)
            else:
                stop.wait(1)
        except Exception as exc:
            log.warning("Queue unavailable (%s), retrying", type(exc).__name__)
            stop.wait(5)


def main():
    logging.basicConfig(level=logging.INFO)
    settings = Settings()
    database = Database(settings)
    database.initialize()
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    run_worker(database, settings, stop)
    database.close()


if __name__ == "__main__":
    main()
