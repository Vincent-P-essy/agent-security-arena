.PHONY: install test lint typecheck evaluate serve docker clean

install:
	uv sync --frozen --all-extras

test:
	uv run pytest --cov=agent_security_arena --cov-report=term-missing

lint:
	uv run ruff check src tests
	uv run ruff format --check src tests

typecheck:
	uv run mypy src

evaluate:
	uv run agent-arena evaluate --suite scenarios/core.yaml --output reports

serve:
	uv run agent-arena serve --host 127.0.0.1 --port 8080

docker:
	docker compose up --build

clean:
	rm -rf .coverage coverage.xml .mypy_cache .pytest_cache .ruff_cache htmlcov reports/*.json reports/*.jsonl reports/*.csv reports/*.md reports/*.sha256
