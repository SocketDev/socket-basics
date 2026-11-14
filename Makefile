.PHONY: lint lint-fix format format-check hooks test

lint:
	uv run --locked --extra dev ruff check
	uv run --locked --extra dev ruff format --check

lint-fix:
	uv run --locked --extra dev ruff check --fix

format:
	uv run --locked --extra dev ruff format

format-check:
	uv run --locked --extra dev ruff format --check

hooks:
	uv run --locked --extra dev pre-commit install

test:
	uv run --locked --extra dev pytest tests/
