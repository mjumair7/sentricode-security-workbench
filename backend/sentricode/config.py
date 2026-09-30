"""Configuration shared by the API and worker."""
from dataclasses import dataclass, field
import os
from pathlib import Path
from urllib.parse import urlparse


def flag(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in {"true", "1", "yes"}


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("SENTRICODE_DATA_DIR", "data")).resolve())
    database_url: str = field(default_factory=lambda: os.getenv("SENTRICODE_DATABASE_URL", ""))
    token: str = field(default_factory=lambda: os.getenv("SENTRICODE_TOKEN", ""))
    public_url: str = field(default_factory=lambda: os.getenv("SENTRICODE_PUBLIC_URL", "http://127.0.0.1:8000").rstrip("/"))
    allowed_origins: str = field(default_factory=lambda: os.getenv("SENTRICODE_ALLOWED_ORIGINS", ""))
    embedded_worker: bool = field(default_factory=lambda: flag("SENTRICODE_EMBEDDED_WORKER", True))
    network_enabled: bool = field(default_factory=lambda: flag("SENTRICODE_NETWORK_ENABLED"))
    max_upload_mb: int = field(default_factory=lambda: int(os.getenv("SENTRICODE_MAX_UPLOAD_MB", "25")))
    max_extracted_mb: int = field(default_factory=lambda: int(os.getenv("SENTRICODE_MAX_EXTRACTED_MB", "100")))
    max_files: int = field(default_factory=lambda: int(os.getenv("SENTRICODE_MAX_FILES", "10000")))
    github_token: str = field(default_factory=lambda: os.getenv("SENTRICODE_GITHUB_TOKEN", ""))
    github_client_id: str = field(default_factory=lambda: os.getenv("SENTRICODE_GITHUB_CLIENT_ID", ""))
    github_client_secret: str = field(default_factory=lambda: os.getenv("SENTRICODE_GITHUB_CLIENT_SECRET", ""))
    github_owner: str = field(default_factory=lambda: os.getenv("SENTRICODE_GITHUB_OWNER", ""))
    openai_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    ai_model: str = field(default_factory=lambda: os.getenv("SENTRICODE_AI_MODEL", "gpt-5-mini"))

    def __post_init__(self):
        self.data_dir = Path(self.data_dir).resolve()
        parsed = urlparse(self.public_url)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path not in {"", "/"}
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise ValueError("SENTRICODE_PUBLIC_URL must be an HTTP(S) origin without credentials, a path, or a query")
        for origin in self.allowed_origins.split(","):
            if not origin.strip():
                continue
            allowed = urlparse(origin.strip())
            if (allowed.scheme not in {"http", "https"} or not allowed.hostname or allowed.path not in {"", "/"}
                    or allowed.username or allowed.password or allowed.query or allowed.fragment):
                raise ValueError("SENTRICODE_ALLOWED_ORIGINS must list explicit HTTP(S) origins")
        if parsed.hostname not in {"localhost", "127.0.0.1", "::1"} and (parsed.scheme != "https" or len(self.token) < 24):
            raise ValueError("Public hosting requires HTTPS and SENTRICODE_TOKEN with at least 24 characters")
        if self.token and len(self.token) < 24:
            raise ValueError("SENTRICODE_TOKEN must contain at least 24 characters")
        if not self.database_url:
            self.database_url = f"sqlite:///{self.data_dir / 'sentricode.db'}"
        if self.database_url.startswith("postgres://"):
            self.database_url = self.database_url.replace("postgres://", "postgresql+psycopg://", 1)
        elif self.database_url.startswith("postgresql://"):
            self.database_url = self.database_url.replace("postgresql://", "postgresql+psycopg://", 1)
        if min(self.max_upload_mb, self.max_extracted_mb, self.max_files) <= 0:
            raise ValueError("Archive limits must be positive")

    @property
    def origins(self) -> set[str]:
        origins = {self.public_url}
        if self.allowed_origins:
            origins.update(value.strip().rstrip("/") for value in self.allowed_origins.split(",") if value.strip())
        elif urlparse(self.public_url).hostname in {"localhost", "127.0.0.1", "::1"}:
            origins.update({"http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8000", "http://127.0.0.1:8000"})
        return origins

    @property
    def github_configured(self) -> bool:
        return bool(self.github_client_id and self.github_client_secret and self.github_owner and self.token)

    @property
    def secure_cookie(self) -> bool:
        return self.public_url.startswith("https://")

    @property
    def jobs_dir(self) -> Path:
        return self.data_dir / "jobs"
