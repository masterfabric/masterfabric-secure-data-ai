# MasterFabric Secure Data AI. Run `make help` for the list of targets.
SHELL := /bin/bash
PY    ?= .venv/bin/python
MODEL ?= $(HOME)/.cache/mf-models/qwen2.5-1.5b-instruct-q4_k_m.gguf
# LLM03 supply chain: the only model file this repo will serve (Qwen2.5-1.5B-Instruct Q4_K_M from Qwen/Qwen2.5-1.5B-Instruct-GGUF)
MODEL_SHA256 := 6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e

.PHONY: help venv test eval pii policy rag llm-up owasp llm-down charts

help: ## Show targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n",$$1,$$2}'

venv: ## Create .venv with uv and the pinned dependencies
	uv venv -p 3.12 .venv && uv pip install -p .venv -r requirements.txt

test: ## Unit tests (28)
	$(PY) -m pytest -q

eval: pii policy rag ## PII, policy and RAG evaluations (no model needed)

pii: ## PII detector precision/recall
	$(PY) eval/pii_eval.py

policy: ## Policy engine on 200,000 synthetic customers
	$(PY) eval/policy_eval.py

rag: ## RAG leakage with no filter, post-filter and pre-filter
	$(PY) eval/rag_eval.py

llm-up: ## Verify the model hash, then start llama-server on 127.0.0.1:61080 (Metal)
	$(PY) -c "from sdai.guard import verify_model; import sys; sys.exit(0 if verify_model('$(MODEL)', '$(MODEL_SHA256)') else 'model hash mismatch: refusing to serve')"
	mkdir -p .out && (nohup llama-server -m $(MODEL) -a qwen --host 127.0.0.1 --port 61080 -ngl 99 -np 2 -c 8192 > .out/llm.log 2>&1 & echo $$! > .out/llm.pid)
	for i in $$(seq 60); do curl -sf 127.0.0.1:61080/health >/dev/null && exit 0; sleep 1; done; exit 1

owasp: ## OWASP LLM01/02/07 attacks against the running model
	$(PY) eval/owasp_llm.py

llm-down: ## Stop the model server started by llm-up
	-kill $$(cat .out/llm.pid) 2>/dev/null; rm -f .out/llm.pid

charts: ## Charts, diagram and hero from results/*.json
	cd viz && ../$(PY) make_charts.py && ../$(PY) make_diagrams.py && ../$(PY) make_hero.py
