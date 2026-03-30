SHELL := /bin/bash

PYTHON_BIN := .venv/bin/python
PIP_BIN := .venv/bin/pip
FRONTEND_DIR := frontend
FRONTEND_DIST := $(FRONTEND_DIR)/dist/index.html
PYTHON_STAMP := .venv/.deps-installed
NODE_STAMP := $(FRONTEND_DIR)/node_modules/.deps-installed

.PHONY: help install bootstrap-model dev build run test clean

help:
	@printf "Available targets:\n"
	@printf "  make install          Install Python and frontend dependencies\n"
	@printf "  make bootstrap-model  Generate the demo model bundle locally\n"
	@printf "  make dev              Run FastAPI and Vite together with reload\n"
	@printf "  make build            Build the React frontend for FastAPI hosting\n"
	@printf "  make run              Build the frontend and run the FastAPI app\n"
	@printf "  make test             Run frontend and backend tests\n"
	@printf "  make clean            Remove built frontend assets and dependency stamps\n"

$(PYTHON_BIN):
	python3 -m venv .venv

$(PYTHON_STAMP): pyproject.toml requirements.txt | $(PYTHON_BIN)
	$(PIP_BIN) install --upgrade pip
	$(PIP_BIN) install -e ".[dev]"
	touch $(PYTHON_STAMP)

$(NODE_STAMP): $(FRONTEND_DIR)/package.json $(FRONTEND_DIR)/package-lock.json
	cd $(FRONTEND_DIR) && npm ci
	touch $(NODE_STAMP)

install: $(PYTHON_STAMP) $(NODE_STAMP)

bootstrap-model: install
	$(PYTHON_BIN) -m baitdetector.ingest --demo
	$(PYTHON_BIN) -m baitdetector.train --training-path data/normalized/latest.parquet
	$(PYTHON_BIN) -m baitdetector.promote

dev: install
	@trap 'kill 0' EXIT INT TERM; \
	$(PYTHON_BIN) -m baitdetector & \
	(cd $(FRONTEND_DIR) && npm run dev) & \
	wait

$(FRONTEND_DIST): install
	cd $(FRONTEND_DIR) && npm run build

build: $(FRONTEND_DIST)

run: build
	$(PYTHON_BIN) -m uvicorn baitdetector.app:create_app --factory --host 127.0.0.1 --port 8000

test: install
	cd $(FRONTEND_DIR) && npm test -- --run
	$(PYTHON_BIN) -m pytest -q

clean:
	rm -rf $(FRONTEND_DIR)/dist
	rm -f $(PYTHON_STAMP) $(NODE_STAMP)
