# Evidence – projet `log-analysis-lab-linux`

Deux niveaux de preuve, à ne pas confondre.

## 1. Preuve reproductible (déjà dans le dépôt)

```bash
python3 data/generate_sample_logs.py
python3 -m loganalyzer analyze \
    --input data/sample/synthetic-3days.jsonl --window 10 --threshold 5 --out reports/
```

Sorties : `reports/report.md` et `reports/findings.csv`, avec **exactement**
9 alertes (voir `data/ground-truth.md`).
`tests/test_synthetic_dataset.py` vérifie que l'analyse retrouve les incidents
injectés et rien d'autre.

## 2. Preuve sur mes journaux réels (à produire)

```bash
./scripts/collect.sh --since "3 days ago" --output raw-logs/journal.jsonl
python3 tools/sanitize.py --input raw-logs/journal.jsonl --output data/real/clean.jsonl
python3 tools/sanitize.py --check data/real/clean.jsonl     # doit répondre 0
python3 -m loganalyzer analyze --input data/real/clean.jsonl --out reports/real/
```

La procédure de provocation des incidents (mots de passe SSH faux, mauvais
`sudo`, `useradd`, service en boucle) est dans
[`../docs/lab-procedure.md`](../docs/lab-procedure.md).

## Ce qui n'est jamais publié

| Fichier | Contenu | Pourquoi |
|---|---|---|
| `raw-logs/*.jsonl` | journaux bruts de ma VM | IP, comptes, nom de machine |
| `data/real/*.jsonl` | journaux assainis | à relire avant publication |
| `mapping*.json` | correspondance réelle → pseudonyme | **reconstitue** les vraies valeurs |
| `reports/real/` | rapport sur mes journaux | contient des extraits de journaux |

Tout cela est dans `.gitignore`. Avant chaque commit :

```bash
git status                                          # rien d'inattendu
python3 tools/sanitize.py --check data/real/clean.jsonl
git grep -nE "([0-9]{1,3}\.){3}[0-9]{1,3}"          # adresses IP
git grep -niE "password|passwd|token|secret"        # secrets
```

## Plan de preuves pour le README

| Fichier | Contenu |
|---|---|
| `screenshots/01-tests-pytest.png` | sortie de `python3 -m pytest` (85 tests) |
| `screenshots/02-analyse-synthetique.png` | sortie de l'analyse + résumé 9 alertes |
| `screenshots/03-rapport-markdown.png` | début de `reports/report.md` |
| `screenshots/04-journaux-reels.png` | analyse de `data/real/clean.jsonl` (assaini) |
| `screenshots/05-sanitize-check.png` | `sanitize.py --check` qui répond 0 |
