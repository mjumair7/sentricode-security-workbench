"""Run the installed app with local configuration; environment variables win."""
import os
from pathlib import Path
import shlex
import sys

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
if (ROOT / ".env").exists():
    for number, line in enumerate((ROOT / ".env").read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key.replace("_", "").isalnum():
            raise SystemExit(f"Invalid .env assignment on line {number}")
        # Parse quotes and comments as data; never evaluate shell expressions.
        values = shlex.split(value, comments=True)
        os.environ.setdefault(key, " ".join(values))

if not (ROOT / "backend/sentricode/static/index.html").is_file():
    raise SystemExit("The dashboard has not been built. Run ./scripts/setup or make build.")

import uvicorn

uvicorn.run("sentricode.api:app", host="127.0.0.1", port=8000, reload="--reload" in sys.argv)

