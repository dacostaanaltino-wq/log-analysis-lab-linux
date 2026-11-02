# log-analysis-lab-linux

[![Python](https://img.shields.io/badge/python-3.14-3776AB)](https://www.python.org/)
[![pytest](https://img.shields.io/badge/pytest-85%20tests%20passing-brightgreen)](tests/)
[![Dépendances](https://img.shields.io/badge/dépendances-bibliothèque%20standard-informational)](pyproject.toml)
[![Licence](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

Analyse de journaux systemd (`journalctl -o json`) et détection d'événements
suspects : force brute SSH, énumération de comptes, abus de `sudo`, création de
comptes, boucles de redémarrage, refus SELinux, connexions hors horaires.

Rapport Markdown + CSV, tests `pytest`, jeu de données synthétique avec sa
vérité terrain, et outil d'anonymisation pour pouvoir publier de vrais journaux
sans données personnelles.

---

## Objectif

Transformer des journaux bruts en **un rapport court, hiérarchisé et vérifiable** :

1. chaque alerte est rattachée à une règle, une sévérité et une référence
   MITRE ATT&CK quand elle existe ;
2. chaque alerte cite **la ligne de journal** qui la justifie (la preuve) ;
3. chaque règle a son test, avec un cas positif **et** un cas négatif ;
4. le jeu de données de démonstration a une **vérité terrain** : l'analyse doit
   retrouver exactement les incidents injectés, sans fausse alerte.

## Contexte

Projet de portfolio (technicien informatique junior en reconversion vers la
cybersécurité). Il réutilise les journaux produits par la VM du projet
`linux-hardening-lab-fedora` : durcir une machine ne sert à rien si personne ne
lit ce qu'elle raconte.

Contrainte forte : **aucun journal réel n'est publié**. Soit il est synthétique,
soit il est anonymisé par `tools/sanitize.py` et vérifié par `--check`.

## Prérequis et outils

| Outil | Version testée | Rôle |
|---|---|---|
| Python | 3.14.8 | l'outil n'utilise que la bibliothèque standard |
| pytest | 9.2.0 | tests (seule dépendance, et seulement pour le développement) |
| systemd / `journalctl` | 259 (Fedora 44) | source des journaux |
| GNU Make | paquet `make` | raccourcis `make demo`, `make test` |

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install pytest
```

Aucune dépendance d'exécution : pas de `pandas`, pas de `scapy`. Le fichier
`pyproject.toml` ne sert qu'à configurer `pytest`.

## Architecture

```text
journalctl -o json  ──►  loganalyzer.parser  ──►  list[Event]
                                                      │
                                    ┌─────────────────┴──────────────────┐
                                    │  loganalyzer.detectors (8 règles)  │
                                    └─────────────────┬──────────────────┘
                                                      ▼
                                             list[Alert] (triées)
                                                      │
                                     ┌────────────────┴───────────────┐
                                     ▼                                ▼
                             reports/report.md                reports/findings.csv
```

```text
log-analysis-lab-linux/
├── loganalyzer/
│   ├── models.py              Event, Alert, Config
│   ├── parser.py              lecture JSON Lines + erreurs explicites
│   ├── helpers.py             fenêtre glissante, extraction IP/compte
│   ├── detectors/             1 module = 1 règle (registre dans __init__.py)
│   ├── report.py              rapport Markdown + CSV
│   └── cli.py                 python -m loganalyzer analyze ...
├── data/
│   ├── generate_sample_logs.py    générateur déterministe
│   ├── ground-truth.md            ce qui est injecté, ce qui doit sortir
│   └── sample/                    journaux + expected_incidents.json
├── tools/sanitize.py          anonymisation avant publication
├── scripts/collect.sh         export journalctl
├── tests/                     85 tests (parseur, règles, rapport, CLI, données)
├── reports/                   rapport d'exemple
└── docs/                      rules.md, journalctl-cheatsheet.md, lab-procedure.md
```

## Étapes pas à pas

### 1. Démonstration immédiate (aucune VM nécessaire)

```bash
make demo
# équivaut à :
python3 data/generate_sample_logs.py
python3 -m loganalyzer analyze --input data/sample/synthetic-3days.jsonl \
        --window 10 --threshold 5 --out reports/
```

Sortie :

```text
Événements analysés : 132
Alertes : 9 (élevées : 3, moyennes : 5, faibles : 1)
Rapport : reports/report.md
CSV     : reports/findings.csv
```

### 2. Tests

```bash
make test          # ou : python3 -m pytest
```

### 3. Sur mes vrais journaux

```bash
./scripts/collect.sh --since "3 days ago" --output raw-logs/journal.jsonl
python3 tools/sanitize.py --input raw-logs/journal.jsonl --output data/real/clean.jsonl
python3 tools/sanitize.py --check data/real/clean.jsonl      # doit répondre 0
python3 -m loganalyzer analyze --input data/real/clean.jsonl --out reports/real/
```

La procédure complète (provoquer les incidents sur ma VM puis vérifier qu'ils
sont détectés) est dans [`docs/lab-procedure.md`](docs/lab-procedure.md).

### 4. Options utiles

```bash
# Changer les seuils
python3 -m loganalyzer analyze --input j.jsonl \
    --window 15 --threshold 8 --min-invalid-users 6 \
    --failures-before-success 3 --sudo-failures 2 --restart-loop 4

# Raisonner à l'heure locale
python3 -m loganalyzer analyze --input j.jsonl --tz Europe/Paris --business-hours 8-19

# N'exécuter qu'une règle (utile pour déboguer)
python3 -m loganalyzer analyze --input j.jsonl --rules ssh_brute_force

# Intégration CI : code de sortie 3 si une alerte élevée existe
python3 -m loganalyzer analyze --input j.jsonl --fail-on high
```

## Vérification et résultats

Extrait de `reports/report.md` (jeu synthétique, seuils par défaut) :

```text
| # | Horodatage (UTC)     | Sévérité | Règle                        | MITRE     | Détail                                                             |
|---|----------------------|----------|------------------------------|-----------|--------------------------------------------------------------------|
| 1 | 2026-10-27 03:12:00  | ÉLEVÉE   | ssh_brute_force              | T1110     | 12 échecs de mot de passe SSH depuis 203.0.113.66 en 10 min ou moins |
| 2 | 2026-10-28 10:42:00  | ÉLEVÉE   | ssh_success_after_failures   | T1078     | Connexion réussie pour « labuser » depuis 203.0.113.77 après 4 échecs |
| 3 | 2026-10-29 11:11:00  | ÉLEVÉE   | account_creation             | T1136     | Utilisateur « testuser » ajouté au groupe « wheel »                |
| 4 | 2026-10-27 14:05:00  | MOYENNE  | ssh_user_enumeration         | T1087     | 7 noms de comptes différents essayés depuis 198.51.100.23          |
| 5 | 2026-10-29 09:30:00  | MOYENNE  | sudo_abuse                   | T1548.003 | 3 mots de passe sudo incorrects pour l'utilisateur « stagiaire »   |
| 9 | 2026-10-29 03:20:00  | FAIBLE   | login_unusual_hours          | —         | Connexion réussie de « labuser » à 03:20, hors plage 8h–19h        |
```

Contrôle automatique (“la détection retrouve exactement les incidents
injectés”) :

```text
$ python3 -m pytest -q
85 passed in 0.22s

$ python3 -m pytest tests/test_synthetic_dataset.py -v
test_la_detection_retrouve_exactement_les_incidents PASSED
test_aucune_alerte_sur_une_regle_non_injectee        PASSED
test_le_fichier_publie_correspond_au_generateur       PASSED
test_le_jeu_de_donnees_ne_contient_que_des_ip_de_documentation PASSED
```

> Remplace ce bloc par la sortie réelle de ma machine après l'exécution de
> `docs/lab-procedure.md`, et ajoute les captures dans une version française du
> README si besoin. Une preuve non exécutée n'est pas une preuve.

## Difficultés rencontrées et solutions

| Difficulté | Cause | Solution retenue |
|---|---|---|
| Double alerte pour un seul scan | `Failed password for invalid user` ressemble à un échec de mot de passe | La règle 1 **exclut** les utilisateurs inexistants ; c'est la règle 2 qui les traite. Décision documentée dans `docs/rules.md` |
| Le rapport disait « 5 échecs » alors qu'il y en avait 12 | la fenêtre glissante s'arrêtait au premier franchissement du seuil | la fonction retourne désormais la fenêtre **la plus dense** |
| Un succès 40 min après des échecs déclenchait la règle 3 | les échecs n'étaient purgés que sur un nouvel échec | purge de la fenêtre avant **chaque** événement (couvert par un test) |
| `group_by` recevait `(event, clé)` au lieu de `(clé, event)` | signature non respectée : `'str' object has no attribute 'message'` | erreur détectée par l'exécution, corrigée sur les 5 règles concernées |
| `19-8` accepté comme plage horaire | priorité des opérateurs dans `if not a and b and c` | parenthèses explicites + test paramétré sur 4 valeurs invalides |
| Fuite de données personnelles dans un journal | `journalctl` contient IP, comptes, hostname | `tools/sanitize.py` + `--check` qui échoue s'il reste une IP réelle |
| Chevauchements entre règles | un incident réel déclenche plusieurs signaux | assumés et documentés ; le jeu synthétique isole chaque règle pour que les tests restent exacts |

## Compétences démontrées

- **Analyse de journaux** : format `journalctl -o json`, champs systemd, corrélation par IP/compte, fenêtres temporelles.
- **Python** : paquet structuré, `dataclasses`, typage, bibliothèque standard seule, CLI `argparse`, séparation parseur / règles / rapport, tests `pytest` avec cas négatifs.
- **Sécurité défensive** : mapping MITRE ATT&CK, sévérités justifiées, limite des faux positifs, conscience de la fatigue d'alerte.
- **Protection des données** : anonymisation cohérente, vérification automatique avant publication, refus de publier des journaux réels.
- **Méthode** : vérité terrain, déterminisme du jeu de données, test qui échoue si le fichier publié ne correspond plus au générateur.

## Limites et améliorations

- Détection **par règles** uniquement : pas de corrélation multi-hôtes, pas d'apprentissage.
- Analyse **hors ligne** : pas de surveillance temps réel (un `tail -f` + `--fail-on` reste possible).
- Pas de géolocalisation des IP, pas d'intégration `fail2ban` automatique.
- Les seuils sont calibrés sur 3 jours de données synthétiques : à ajuster sur une vraie machine.
- Améliorations possibles : fenêtre de maintenance pour `account_creation`, agrégation multi-fichiers (`--input` répétable), export JSON pour un tableau de bord, règles `sigma`, corrélation avec `auditd`.
- Pas de `bats`/tests d'intégration pour `scripts/collect.sh` (seulement `shellcheck`).

## Ressources

- `man journalctl`, `man systemd.journal-fields`, `man systemd.exec`
- MITRE ATT&CK — <https://attack.mitre.org/>
  (T1110 brute force, T1087 account discovery, T1078 valid accounts, T1136 create account, T1548.003 sudo and su)
- ANSSI-BP-028 (journalisation et traçabilité) — <https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux>
- Documentation Python : `datetime`, `zoneinfo`, `argparse`, `csv`, `dataclasses`
- pytest — <https://docs.pytest.org/>

## Ce que j'ai appris

`À COMPLÉTER PAR ANALTINO`
