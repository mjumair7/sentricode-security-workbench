.PHONY: setup start build test check dev-web docker stop
PYTHON ?= .venv/bin/python

setup:
	./scripts/setup

start:
	./scripts/start

build:
	cd frontend && corepack pnpm build
	$(PYTHON) scripts/copy_frontend.py

test:
	$(PYTHON) -m pytest

check:
	$(PYTHON) -m pytest
	cd frontend && corepack pnpm typecheck

dev-web:
	cd frontend && corepack pnpm dev

docker:
	docker compose up -d --build

stop:
	docker compose stop

