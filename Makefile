.PHONY: install test lint typecheck evaluate serve docker clean

install:
	python -m pip install -e '.[dev]'

test:
	pytest --cov=agent_security_arena --cov-report=term-missing

lint:
	ruff check src tests
	ruff format --check src tests

typecheck:
	mypy src

evaluate:
	agent-arena evaluate --suite scenarios/core.yaml --output reports

serve:
	agent-arena serve --host 127.0.0.1 --port 8080

docker:
	docker compose up --build

clean:
	rm -rf .coverage .pytest_cache .ruff_cache htmlcov reports/*.json reports/*.csv reports/*.md

