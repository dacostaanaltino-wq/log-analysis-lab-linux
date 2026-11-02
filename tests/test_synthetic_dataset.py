"""Tests du jeu de données synthétique : la détection doit retrouver exactement
les incidents injectés, et le fichier publié doit correspondre au générateur.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import pytest

from loganalyzer.detectors import RULES, run_all
from loganalyzer.models import Config

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / "data"
SAMPLE = DATA_DIR / "sample" / "synthetic-3days.jsonl"
TRUTH = DATA_DIR / "sample" / "expected_incidents.json"

# Le générateur est un script, pas un module du paquet : on l'importe par son chemin.
sys.path.insert(0, str(DATA_DIR))
import generate_sample_logs as generator  # noqa: E402


def _config_from_truth(truth: dict) -> Config:
    """Reconstruit la configuration attendue depuis le fichier de vérité terrain."""
    parameters = dict(truth["parameters"])
    parameters["business_hours"] = tuple(parameters["business_hours"])
    return Config(**parameters)


@pytest.fixture(scope="module")
def truth() -> dict:
    return json.loads(TRUTH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def detected_rules(truth: dict) -> Counter:
    """Lance l'analyse complète sur le jeu de données publié."""
    from loganalyzer.parser import load_events

    events = load_events(SAMPLE)
    alerts = run_all(events, _config_from_truth(truth))
    return Counter(alert.rule for alert in alerts)


def test_la_detection_retrouve_exactement_les_incidents(truth: dict, detected_rules: Counter) -> None:
    """C'est le test central : aucun incident oublié, aucune fausse alerte."""
    assert dict(sorted(detected_rules.items())) == truth["expected_alerts"]


def test_aucune_alerte_sur_une_regle_non_injectee(truth: dict, detected_rules: Counter) -> None:
    assert set(detected_rules) <= set(truth["expected_alerts"])


def test_toutes_les_regles_du_ground_truth_existent(truth: dict) -> None:
    assert set(truth["expected_alerts"]) <= set(RULES)


def test_le_fichier_publie_correspond_au_generateur(truth: dict) -> None:
    """Si ce test échoue, il faut relancer data/generate_sample_logs.py."""
    generated, _ = generator.build_dataset(days=truth["days"], seed=truth["seed"])
    published = [
        json.loads(line)
        for line in SAMPLE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert generated == published


def test_le_generateur_est_deterministe() -> None:
    first, incidents_first = generator.build_dataset()
    second, incidents_second = generator.build_dataset()
    assert first == second
    assert incidents_first == incidents_second


def test_le_jeu_de_donnees_ne_contient_que_des_ip_de_documentation() -> None:
    """Aucune adresse personnelle ne doit apparaître dans un dépôt public."""
    allowed = ("192.0.2.", "198.51.100.", "203.0.113.", "127.")
    text = SAMPLE.read_text(encoding="utf-8")
    for line in text.splitlines():
        record = json.loads(line)
        message = record["MESSAGE"]
        import re

        for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message):
            assert candidate.startswith(allowed), f"IP non documentaire : {candidate}"


def test_le_nombre_d_incidents_est_coherent(truth: dict) -> None:
    assert len(truth["incidents"]) == sum(truth["expected_alerts"].values())
