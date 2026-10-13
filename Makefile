PY     ?= .venv/bin/python
REPORT ?= examples/glass-heron.md
JOBS   ?= 8
export PYTHONPATH := src

.DEFAULT_GOAL := help
.PHONY: help install download train evaluate extract test lint format clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-9s\033[0m %s\n", $$1, $$2}'

install: ## Create .venv and install Gleaner with dev tools
	python3 -m venv .venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"

download: ## Fetch TRAM, ATT&CK v19.2 and AnnoCTR at pinned commits (88 MB), verify SHA-256
	$(PY) -m gleaner download

train: ## Select hyper-parameters and train the CRF taggers and technique classifier (~25 min)
	$(PY) -m gleaner train --n-jobs $(JOBS)

evaluate: ## Run every evaluation protocol -> reports/ (~1 h on a laptop CPU)
	$(PY) -m gleaner evaluate --n-jobs $(JOBS)

extract: ## Extract a report (REPORT=...) to Markdown, JSON and a validated STIX bundle in runtime/
	$(PY) -m gleaner extract $(REPORT) -f md -o runtime/$(notdir $(REPORT)).md
	$(PY) -m gleaner extract $(REPORT) -f json -o runtime/$(notdir $(REPORT)).json
	$(PY) -m gleaner extract $(REPORT) -f stix -o runtime/$(notdir $(REPORT)).stix.json
	$(PY) -m gleaner validate runtime/$(notdir $(REPORT)).stix.json

test: ## Run the test suite (fixtures only: no dataset or network needed)
	$(PY) -m pytest --cov --cov-report=term-missing

lint: ## Lint and check formatting
	$(PY) -m ruff check src tests
	$(PY) -m ruff format --check src tests

format: ## Auto-format the code
	$(PY) -m ruff check --fix src tests
	$(PY) -m ruff format src tests

clean: ## Remove caches and runtime output (keeps data/, models/ and reports/)
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov runtime
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
