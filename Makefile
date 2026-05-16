PYTHON ?= python3
PORT ?= 8000

.PHONY: install test lint run clean

install:
	$(PYTHON) -m pip install -r requirements-dev.txt

test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

lint:
	$(PYTHON) -m ruff check services tools scripts tests

run:
	$(PYTHON) scripts/start_product.py --port $(PORT)

clean:
	rm -rf .pytest_cache .ruff_cache htmlcov build dist
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
