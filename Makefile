# ==============================================================================
# AegisOps DevSecOps Pipeline Makefile
# Unified Developer & Security Automation Workflow
# ==============================================================================
SHELL := /bin/bash
.DEFAULT_GOAL := help

PYTHON := services/python-service/.venv/bin/python3
PYTEST := services/python-service/.venv/bin/pytest

.PHONY: help
help:
	@echo "AegisOps DevSecOps Pipeline — CLI Automation Targets:"
	@echo "  make setup          Install all local dependencies and virtual environments"
	@echo "  make test           Execute complete test suite (frontend, api, python, policy)"
	@echo "  make lint           Run type-checkers and syntax linters"
	@echo "  make build          Build hardened multi-stage Docker container images"
	@echo "  make up             Start the multi-tier application stack with healthchecks"
	@echo "  make down           Gracefully stop and clean up containers and network"
	@echo "  make scan-secrets   Run Gitleaks secret scanning"
	@echo "  make scan-sast      Run Semgrep and Bandit SAST scanners"
	@echo "  make scan-deps      Run npm audit and pip-audit SCA scanners"
	@echo "  make scan-container Run Trivy container vulnerability scanner"
	@echo "  make scan-iac       Run Checkov IaC & Dockerfile configuration scanner"
	@echo "  make scan-dast      Run OWASP ZAP baseline scan against running API"
	@echo "  make security       Execute the Central Security Policy Engine release gate"
	@echo "  make sbom           Generate CycloneDX and SPDX Software Bill of Materials"
	@echo "  make sign           Execute Cosign cryptographic signing and verification demo"
	@echo "  make clean          Clean temporary build artifacts, reports, and caches"

.PHONY: setup
setup:
	@echo "[AegisOps] Setting up Frontend dependencies..."
	cd frontend && npm install
	@echo "[AegisOps] Setting up Node API dependencies..."
	cd services/api && npm install
	@echo "[AegisOps] Setting up Python Service virtualenv..."
	python3 -m venv services/python-service/.venv
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r services/python-service/requirements.txt -r services/python-service/requirements-dev.txt -r security/requirements.txt
	@echo "[AegisOps] Setup completed successfully."

.PHONY: test
test:
	@echo "[AegisOps Test] Running Frontend Unit & Component Tests..."
	cd frontend && npm test
	@echo "[AegisOps Test] Running Node.js API Gateway Tests..."
	cd services/api && npm test
	@echo "[AegisOps Test] Running Python Security Microservice Tests..."
	$(PYTEST) -v services/python-service/tests
	@echo "[AegisOps Test] Running Central Security Policy Engine Tests..."
	PYTHONPATH=. $(PYTEST) -v security/tests
	@echo "[AegisOps Test] All test suites passed successfully!"

.PHONY: lint
lint:
	@echo "[AegisOps Lint] Verifying Frontend TypeScript..."
	cd frontend && npx tsc --noEmit
	@echo "[AegisOps Lint] Verifying Node API TypeScript..."
	cd services/api && npx tsc --noEmit
	@echo "[AegisOps Lint] Verifying Python syntax..."
	$(PYTHON) -m py_compile services/python-service/app/*.py security/policy/*.py

.PHONY: build
build:
	@echo "[AegisOps Build] Building hardened Docker images via Compose..."
	docker compose build

.PHONY: up
up:
	@echo "[AegisOps Up] Starting containers and waiting for health readiness..."
	docker compose up -d
	@echo "[AegisOps Up] Checking container status..."
	docker compose ps

.PHONY: down
down:
	@echo "[AegisOps Down] Stopping application stack..."
	docker compose down

.PHONY: scan-secrets
scan-secrets:
	@echo "[AegisOps Scanner] Running Gitleaks secret detection..."
	mkdir -p reports
	docker run --rm -v $(PWD):/path zricethezav/gitleaks:v8.21.2 detect --source="/path" --config="/path/.gitleaks.toml" --report-path="/path/reports/gitleaks.json" --report-format="json" --exit-code=0 || true
	@if [ ! -s reports/gitleaks.json ]; then echo "[]" > reports/gitleaks.json; fi

.PHONY: scan-sast
scan-sast:
	@echo "[AegisOps Scanner] Running Semgrep SAST..."
	mkdir -p reports
	docker run --rm -v $(PWD):/src returntocorp/semgrep:1.98.0 semgrep scan --config=/src/security/config/.semgrep.yml --json --output=/src/reports/semgrep.json /src/frontend/src /src/services/api/src /src/services/python-service/app || true
	@if [ ! -s reports/semgrep.json ]; then echo '{"results":[],"errors":[]}' > reports/semgrep.json; fi
	@echo "[AegisOps Scanner] Running Bandit Python SAST..."
	docker run --rm -v $(PWD):/src pycqa/bandit:1.8.0 -c /src/security/config/bandit.yaml -r /src/services/python-service/app -f json -o /src/reports/bandit.json || true
	@if [ ! -s reports/bandit.json ]; then echo '{"results":[],"errors":[]}' > reports/bandit.json; fi

.PHONY: scan-deps
scan-deps:
	@echo "[AegisOps Scanner] Running npm audit (API Gateway)..."
	mkdir -p reports
	cd services/api && npm audit --omit=dev --json > ../../reports/npm_audit.json || true
	@echo "[AegisOps Scanner] Running pip-audit (Python Service)..."
	docker run --rm -v $(PWD)/services/python-service:/src trailofbits/pip-audit:v2.7.3 -r /src/requirements.txt -f json -o /src/../../reports/pip_audit.json || true
	@if [ ! -s reports/pip_audit.json ]; then echo '{"dependencies":[]}' > reports/pip_audit.json; fi

.PHONY: scan-container
scan-container:
	@echo "[AegisOps Scanner] Running Trivy on built image aegisops/api:1.0.0..."
	mkdir -p reports
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v $(PWD)/reports:/reports aquasec/trivy:latest image --severity CRITICAL,HIGH --format json --output /reports/trivy.json aegisops/api:1.0.0 || true
	@if [ ! -s reports/trivy.json ]; then echo '{"Results":[]}' > reports/trivy.json; fi

.PHONY: scan-iac
scan-iac:
	@echo "[AegisOps Scanner] Running Checkov on Dockerfiles and Compose..."
	mkdir -p reports
	docker run --rm -v $(PWD):/tf bridgecrew/checkov:3.2.355 --config-file /tf/security/config/checkov.yaml -d /tf -o json --output-file-path /tf/reports || true
	@if [ -f reports/results_dockerfile.json ]; then cp reports/results_dockerfile.json reports/checkov.json; elif [ ! -s reports/checkov.json ]; then echo '{"results":{"passed_checks":[],"failed_checks":[]}}' > reports/checkov.json; fi

.PHONY: scan-dast
scan-dast:
	@echo "[AegisOps Scanner] Running OWASP ZAP Baseline DAST..."
	mkdir -p reports
	docker run --rm --network host -v $(PWD)/security/config:/zap/wrk/:ro -v $(PWD)/reports:/zap/reports/:rw zaproxy/zap-stable:2.15.0 zap-baseline.py -t http://127.0.0.1:8000/health -c zap-baseline.conf -J /zap/reports/zap.json -r /zap/reports/zap-report.html -I || true
	@if [ ! -s reports/zap.json ]; then echo '{"site":[]}' > reports/zap.json; fi

.PHONY: security
security:
	@echo "[AegisOps Gate] Evaluating Central Security Policy Engine..."
	mkdir -p reports
	PYTHONPATH=. $(PYTHON) security/policy/cli.py --config security/policy_config.yaml --reports-dir reports

.PHONY: sbom
sbom:
	@bash scripts/generate_sbom.sh reports/sbom

.PHONY: sign
sign:
	@bash scripts/sign_artifacts.sh

.PHONY: clean
clean:
	@echo "[AegisOps] Cleaning build artifacts and reports..."
	rm -rf reports dist .pytest_cache frontend/dist services/api/dist
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@echo "[AegisOps] Clean complete."
