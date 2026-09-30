"""The database stores reports and job state, never full source checkouts."""
from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def uid() -> str:
    return uuid4().hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Repository(Base):
    __tablename__ = "repositories"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    identity: Mapped[str] = mapped_column(String(400), unique=True)
    name: Mapped[str] = mapped_column(String(120))
    source: Mapped[str] = mapped_column(String(20))
    url: Mapped[str | None] = mapped_column(String(400), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id"), index=True)
    repository_name: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    mode: Mapped[str] = mapped_column(String(20), default="standard")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    stage: Mapped[str] = mapped_column(String(80), default="queued")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    report: Mapped[dict] = mapped_column(JSON, default=dict)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(200), index=True)
    status: Mapped[str] = mapped_column(String(30), default="open")
    reason: Mapped[str] = mapped_column(Text, default="")
    data: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    action: Mapped[str] = mapped_column(String(100))
    resource: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class Preference(Base):
    __tablename__ = "preferences"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)
