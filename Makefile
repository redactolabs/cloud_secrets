.PHONY: install test test-cov format lint clean
export PROJECT=.

black-check: ## Check the code base
	autoflake -cd --remove-all-unused-imports -r --quiet ./$(PROJECT)
	poetry run black ./$(PROJECT) --check --diff

black: ## Check the code base, and fix it
	autoflake --in-place --remove-all-unused-imports -r ./$(PROJECT)
	poetry run black ./$(PROJECT)

tests: black
	# Run with coverage
	poetry run pytest -s

install:
	poetry install

test-cov:
	poetry run pytest --cov=cloud_secrets --cov-report=term-missing

lint:
	poetry run flake8 .
	poetry run mypy .

clean:
	rm -rf dist/ build/ *.egg-info
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name "*.egg" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +