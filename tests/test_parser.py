"""Tests du parseur : format journalctl, erreurs, tri."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from loganalyzer.parser import ParseError, iter_events, load_events, parse_line


def _line(microseconds: int, message: str, **extra: str) -> str:
    """Construit une ligne JSON de journal pour les tests."""
    payload = {
        "__REALTIME_TIMESTAMP": str(microseconds),
        "MESSAGE": message,
        "_HOSTNAME": "lab-vm",
        "SYSLOG_IDENTIFIER": "sshd",
        "PRIORITY": "4",
        **extra,
    }
    return json.dumps(payload)


def test_parse_line_lit_les_champs_principaux() -> None:
    line = _line(1_793_059_200_000_000, "Failed password for admin from 203.0.113.66 port 22 ssh2")
    event = parse_line(line)

    assert event.message.startswith("Failed password for admin")
    assert event.identifier == "sshd"
    assert event.hostname == "lab-vm"
    assert event.priority == 4
    assert event.timestamp == datetime(2026, 10, 27, 0, 0, tzinfo=timezone.utc)


def test_parse_line_accepte_un_horodatage_numerique() -> None:
    line = json.dumps({"__REALTIME_TIMESTAMP": 1_793_059_200_000_000, "MESSAGE": "ok"})
    assert parse_line(line).timestamp.year == 2026


def test_parse_line_refuse_un_json_invalide() -> None:
    with pytest.raises(ParseError, match="JSON invalide"):
        parse_line("{pas du json")


def test_parse_line_refuse_un_objet_qui_n_est_pas_un_dictionnaire() -> None:
    with pytest.raises(ParseError, match="dictionnaire"):
        parse_line("[1, 2, 3]")


def test_parse_line_exige_un_horodatage() -> None:
    with pytest.raises(ParseError, match="__REALTIME_TIMESTAMP"):
        parse_line(json.dumps({"MESSAGE": "sans horodatage"}))


def test_priority_absente_vaut_info() -> None:
    line = json.dumps({"__REALTIME_TIMESTAMP": "1793059200000000", "MESSAGE": "x"})
    assert parse_line(line).priority == 6


def test_iter_events_ignore_les_lignes_vides(tmp_path) -> None:
    path = tmp_path / "journal.jsonl"
    path.write_text(_line(1_793_059_200_000_000, "premier") + "\n\n" + _line(1_793_059_260_000_000, "second") + "\n")
    messages = [event.message for event in iter_events(path)]
    assert messages == ["premier", "second"]


def test_iter_events_indique_le_numero_de_ligne(tmp_path) -> None:
    path = tmp_path / "journal.jsonl"
    path.write_text(_line(1_793_059_200_000_000, "ok") + "\n{invalide\n")
    with pytest.raises(ParseError, match="ligne 2"):
        list(iter_events(path))


def test_load_events_trie_par_horodatage(tmp_path) -> None:
    path = tmp_path / "journal.jsonl"
    path.write_text(
        _line(1_793_059_400_000_000, "deuxieme")
        + "\n"
        + _line(1_793_059_200_000_000, "premier")
        + "\n"
    )
    events = load_events(path)
    assert [event.message for event in events] == ["premier", "deuxieme"]


def test_fichier_absent_leve_file_not_found(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        list(iter_events(tmp_path / "absent.jsonl"))
