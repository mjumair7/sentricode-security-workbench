from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from .config import Settings
from .models import Base


class Database:
    def __init__(self, settings: Settings):
        settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        settings.jobs_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        sqlite = settings.database_url.startswith("sqlite")
        self.engine = create_engine(settings.database_url, connect_args={"check_same_thread": False, "timeout": 30} if sqlite else {}, pool_pre_ping=True)
        if sqlite:
            @event.listens_for(self.engine, "connect")
            def configure_sqlite(connection, _):
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("PRAGMA journal_mode=WAL")
        self.session = sessionmaker(self.engine, expire_on_commit=False)

    def initialize(self):
        Base.metadata.create_all(self.engine)
        if self.engine.url.get_backend_name() == "sqlite":
            filename = self.engine.url.database
            if filename and filename != ":memory:":
                for suffix in ("", "-wal", "-shm"):
                    path = Path(filename + suffix)
                    if path.exists():
                        path.chmod(0o600)

    def close(self):
        self.engine.dispose()
