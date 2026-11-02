# Makefile du lab d'analyse de journaux.
#
#   make demo   régénère le jeu de données synthétique et produit reports/
#   make test   lance pytest
#   make clean  supprime les rapports et les fichiers Python compilés

PYTHON ?= python3
SAMPLE := data/sample/synthetic-3days.jsonl
REPORTS := reports

.PHONY: help demo sample analyze test clean

help:
	@echo "make demo    - jeu de données synthétique + rapport d'exemple"
	@echo "make sample  - génère seulement data/sample/"
	@echo "make analyze - analyse data/sample/ vers reports/"
	@echo "make test    - pytest"
	@echo "make clean   - supprime reports/ et __pycache__"

demo: sample analyze
	@echo "Rapport prêt : $(REPORTS)/report.md"

sample:
	$(PYTHON) data/generate_sample_logs.py

analyze: $(SAMPLE)
	$(PYTHON) -m loganalyzer analyze --input $(SAMPLE) --window 10 --threshold 5 --out $(REPORTS)

test:
	$(PYTHON) -m pytest

clean:
	rm -rf $(REPORTS)/report.md $(REPORTS)/findings.csv
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
