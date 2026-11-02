"""Tests de l'interface en ligne de commande."""

from __future__ import annotations

import json

import pytest

from loganalyzer.cli import _business_hours, main


def _journal(path, messages):
    """Écrit un petit journal JSON Lines à partir de (microsecondes, message)."""
    with path.open("w", encoding="utf-8") as handle:
        for micro, message in messages:
            handle.write(
                json.dumps(
                    {
                        "__REALTIME_TIMESTAMP": str(micro),
                        "MESSAGE": message,
                        "SYSLOG_IDENTIFIER": "sshd",
                        "PRIORITY": "4",
                        "_HOSTNAME": "lab-vm",
                    }
                )
                + "\n"
            )
    return path


def test_analyse_produit_les_rapports(tmp_path, capsys) -> None:
    base = 1_793_059_200_000_000
    journal = _journal(
        tmp_path / "j.jsonl",
        [(base + index * 1_000_000, "Failed password for admin from 203.0.113.66 port 50000 ssh2") for index in range(6)],
    )
    assert main(["analyze", "--input", str(journal), "--out", str(tmp_path / "out")]) == 0
    assert (tmp_path / "out" / "report.md").exists()
    assert (tmp_path / "out" / "findings.csv").exists()
    assert "Alertes : 1" in capsys.readouterr().out


def test_fichier_absent_retourne_2(tmp_path) -> None:
    assert main(["analyze", "--input", str(tmp_path / "absent.jsonl")]) == 2


def test_journal_invalide_retourne_2(tmp_path) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text("{pas du json}\n")
    assert main(["analyze", "--input", str(path)]) == 2


def test_regle_inconnue_retourne_2(tmp_path) -> None:
    journal = _journal(tmp_path / "j.jsonl", [(1_793_059_200_000_000, "ok")])
    assert main(["analyze", "--input", str(journal), "--rules", "regle_qui_n_existe_pas"]) == 2


def test_fail_on_high_retourne_3(tmp_path) -> None:
    base = 1_793_059_200_000_000
    journal = _journal(
        tmp_path / "j.jsonl",
        [(base + index * 1_000_000, "Failed password for admin from 203.0.113.66 port 50000 ssh2") for index in range(12)],
    )
    assert main(["analyze", "--input", str(journal), "--out", str(tmp_path / "o"), "--fail-on", "high"]) == 3


def test_fail_on_high_ne_declenche_pas_sans_alerte_haute(tmp_path) -> None:
    journal = _journal(tmp_path / "j.jsonl", [(1_793_059_200_000_000, "Started chronyd.service")])
    assert main(["analyze", "--input", str(journal), "--out", str(tmp_path / "o"), "--fail-on", "high"]) == 0


def test_rules_filtre_les_detecteurs(tmp_path) -> None:
    base = 1_793_059_200_000_000
    journal = _journal(
        tmp_path / "j.jsonl",
        [(base + index * 1_000_000, "Failed password for admin from 203.0.113.66 port 50000 ssh2") for index in range(6)],
    )
    assert main(["analyze", "--input", str(journal), "--out", str(tmp_path / "o"), "--rules", "sudo_abuse"]) == 0
    assert "Aucune alerte" in (tmp_path / "o" / "report.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("value", ["8-19", "0-24", "22-23"])
def test_business_hours_accepte_les_plages_valides(value: str) -> None:
    assert isinstance(_business_hours(value), tuple)


@pytest.mark.parametrize("value", ["19-8", "abc", "8", "25-26"])
def test_business_hours_refuse_les_plages_invalides(value: str) -> None:
    with pytest.raises(Exception):
        _business_hours(value)
