# syntax=docker/dockerfile:1
FROM node:22-alpine AS web
WORKDIR /web
ENV NEXT_TELEMETRY_DISABLED=1
RUN corepack enable
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN corepack pnpm install --frozen-lockfile
COPY frontend/ ./
RUN corepack pnpm build

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SENTRICODE_DATA_DIR=/data
WORKDIR /app
RUN groupadd --gid 10001 sentricode \
    && useradd --uid 10001 --gid sentricode --no-create-home sentricode \
    && mkdir /data \
    && chown sentricode:sentricode /data
COPY requirements.lock requirements-postgres.lock ./
RUN pip install -r requirements.lock -r requirements-postgres.lock
COPY pyproject.toml README.md LICENSE ./
COPY backend/ ./backend/
COPY --from=web /web/out/ ./backend/sentricode/static/
RUN pip install --no-deps .
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import os,urllib.request,urllib.parse; origin=os.environ.get('SENTRICODE_PUBLIC_URL','http://127.0.0.1:8000'); request=urllib.request.Request('http://127.0.0.1:8000/api/v1/health',headers={'Host':urllib.parse.urlsplit(origin).netloc}); urllib.request.urlopen(request,timeout=3)"
CMD ["uvicorn", "sentricode.api:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
