PYTHON ?= python3
INPUT ?= examples/ecu_risks.json
ARTIFACTS ?= artifacts

.PHONY: install test demo clean

install:
	$(PYTHON) -m pip install -e .

test:
	$(PYTHON) -m unittest discover -s tests -v

demo:
	$(PYTHON) -m automotive_security_bench assess --input $(INPUT) --json-out $(ARTIFACTS)/assessment.json --html-out $(ARTIFACTS)/assessment.html

clean:
	rm -rf $(ARTIFACTS) .coverage .pytest_cache build dist
