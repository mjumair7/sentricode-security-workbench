"""Copy the static Next.js export into the Python application package."""
from pathlib import Path
import shutil

root = Path(__file__).resolve().parent.parent
source = root / "frontend/out"
destination = root / "backend/sentricode/static"
if not (source / "index.html").is_file():
    raise SystemExit("Build the frontend before copying it: cd frontend && corepack pnpm build")
if destination.exists():
    shutil.rmtree(destination)
shutil.copytree(source, destination)
print("Dashboard copied into the application.")

