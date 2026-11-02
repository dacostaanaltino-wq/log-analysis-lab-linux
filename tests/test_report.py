"""Tests du rapport Markdown et du CSV."""

from __future__ import annotations

import csv
from collections.abc import Callable
from datetime import datetime, timezone

from loganalyzer.models import Alert, Config
from loganalyzer.report import CSV_COLUMNS, build_report, severity_counts, write_reports


def _alert(severity: str = "high") -> Alert:
    return Alert(
        rule="ssh_brute_force",
        severity=severity,
        timestamp=datetime(2026, 10, 27, 3, 12, tzinfo=timezone.utc),
        message="12 échecs de mot de passe SSH depuis 203.0.113.66",
        evidence="Failed password for admin from 203.0.113.66 port 50011 ssh2",
        recommendation="Bloquer l'IP.",
        mitre="T1110",
        count=12,
    )


def test_rapport_contient_le_resume_et_la_preuve(make_event: Callable[..., object]) -> None:
    events = [make_event(minutes=0, message="Started chronyd.service")]  # type: ignore[arg-type]
    report = build_report(events, [_alert()], "journal.jsonl", Config())  # type: ignore[arg-type]

    assert "# Rapport d'analyse de journaux" in report
    assert "Événements analysés" in report
    assert "ssh_brute_force" in report
    assert "203.0.113.66" in report
    assert "T1110" in report
    assert "| **Total** | **1** |" in report


def test_rapport_sans_alerte_le_dit_clairement(make_event: Callable[..., object]) -> None:
    events = [make_event(minutes=0, message="Started chronyd.service")]  # type: ignore[arg-type]
    report = build_report(events, [], "journal.jsonl", Config())  # type: ignore[arg-type]
    assert "Aucune alerte" in report
    assert "ne prouve pas l'absence d'attaque" in report


def test_rapport_echappe_les_barres_verticales(make_event: Callable[..., object]) -> None:
    alert = Alert(
        rule="test",
        severity="low",
        timestamp=datetime(2026, 10, 27, tzinfo=timezone.utc),
        message="message avec | une barre",
        evidence="ligne | de journal",
    )
    report = build_report([], [alert], "x.jsonl", Config())  # type: ignore[arg-type]
    assert "\\|" in report


def test_csv_a_les_colonnes_attendues(tmp_path, make_event: Callable[..., object]) -> None:
    events = [make_event(minutes=0, message="x")]  # type: ignore[arg-type]
    _, csv_path = write_reports(events, [_alert()], "journal.jsonl", Config(), tmp_path)  # type: ignore[arg-type]

    with csv_path.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    assert rows[0].keys() == set(CSV_COLUMNS)
    assert rows[0]["severity"] == "high"
    assert rows[0]["rule"] == "ssh_brute_force"
    assert rows[0]["timestamp_utc"] == "2026-10-27 03:12:00"
    # La preuve complète est dans le CSV (non tronquée).
    assert rows[0]["evidence"].endswith("ssh2")


def test_write_reports_cree_les_deux_fichiers(tmp_path, make_event: Callable[..., object]) -> None:
    events = [make_event(minutes=0, message="x")]  # type: ignore[arg-type]
    report_path, csv_path = write_reports(events, [_alert()], "j.jsonl", Config(), tmp_path / "out")
    assert report_path.exists()
    assert csv_path.exists()
    assert report_path.name == "report.md"


def test_severity_counts_toujours_les_trois_cles() -> None:
    assert severity_counts([]) == {"low": 0, "medium": 0, "high": 0}
    assert severity_counts([_alert("high"), _alert("low")]) == {"low": 1, "medium": 0, "high": 1}
