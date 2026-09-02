.PHONY: test install

install:
	python3 -m pip install -e ".[dev]"

test:
	python3 -m pytest -q
