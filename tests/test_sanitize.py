"""Tests de l'outil d'anonymisation des journaux réels."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import sanitize  # noqa: E402


def test_ip_pseudonymisee_de_facon_coherente() -> None:
    pseudo = sanitize.Pseudonymizer()
    first = pseudo.ip("10.20.30.40")
    second = pseudo.ip("10.20.30.40")
    assert first == second
    assert first.startswith("192.0.2.")


def test_ip_de_documentation_laissee_intacte() -> None:
    pseudo = sanitize.Pseudonymizer()
    assert pseudo.ip("203.0.113.66") == "203.0.113.66"


def test_utilisateur_pseudonymise() -> None:
    pseudo = sanitize.Pseudonymizer()
    assert pseudo.user("altinocost") == "utilisateur-1"
    assert pseudo.user("altinocost") == "utilisateur-1"
    assert pseudo.user("stagiaire") == "utilisateur-2"


def test_root_n_est_pas_pseudonymise() -> None:
    pseudo = sanitize.Pseudonymizer()
    assert pseudo.user("root") == "root"


def test_texte_anonymise_utilisateur_et_ip() -> None:
    pseudo = sanitize.Pseudonymizer()
    message = "Failed password for alice from 10.20.30.40 port 50011 ssh2"
    clean = pseudo.text(message)
    assert "alice" not in clean
    assert "10.20.30.40" not in clean
    assert "utilisateur-1" in clean


def test_hostname_pseudonymise() -> None:
    pseudo = sanitize.Pseudonymizer()
    record = sanitize.sanitize_record({"MESSAGE": "ok", "_HOSTNAME": "pc-de-la-maison"}, pseudo)
    assert record["_HOSTNAME"] == "hote-lab-1"


def test_sanitize_file_ecrit_un_fichier_propre(tmp_path) -> None:
    source = tmp_path / "raw.jsonl"
    source.write_text(
        json.dumps(
            {
                "__REALTIME_TIMESTAMP": "1793059200000000",
                "MESSAGE": "Failed password for alice from 10.20.30.40 port 22 ssh2",
                "_HOSTNAME": "pc-maison",
                "SYSLOG_IDENTIFIER": "sshd",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    destination = tmp_path / "clean.jsonl"
    assert sanitize.sanitize_file(source, destination) == 1

    record = json.loads(destination.read_text(encoding="utf-8").strip())
    assert "alice" not in json.dumps(record)
    assert "10.20.30.40" not in json.dumps(record)
    assert sanitize.find_leftover_ips(destination) == []


def test_sanitize_file_ignore_les_lignes_invalides(tmp_path, capsys) -> None:
    source = tmp_path / "raw.jsonl"
    source.write_text(
        json.dumps({"__REALTIME_TIMESTAMP": "1793059200000000", "MESSAGE": "ok"}) + "\n{pas du json\n",
        encoding="utf-8",
    )
    destination = tmp_path / "clean.jsonl"
    assert sanitize.sanitize_file(source, destination) == 1
    assert "ignorée" in capsys.readouterr().err


def test_check_detecte_une_ip_reelle(tmp_path, capsys) -> None:
    path = tmp_path / "fuite.jsonl"
    path.write_text(json.dumps({"MESSAGE": "connexion depuis 10.20.30.40"}) + "\n", encoding="utf-8")
    assert sanitize.main(["--check", str(path)]) == 1
    assert "10.20.30.40" in capsys.readouterr().err


def test_check_accepte_un_fichier_propre(tmp_path, capsys) -> None:
    path = tmp_path / "propre.jsonl"
    path.write_text(json.dumps({"MESSAGE": "connexion depuis 203.0.113.66"}) + "\n", encoding="utf-8")
    assert sanitize.main(["--check", str(path)]) == 0


def test_mapping_out_est_ecrit(tmp_path) -> None:
    source = tmp_path / "raw.jsonl"
    source.write_text(json.dumps({"MESSAGE": "for alice from 10.20.30.40 port 1"}) + "\n", encoding="utf-8")
    mapping = tmp_path / "mapping.json"
    sanitize.sanitize_file(source, tmp_path / "clean.jsonl", mapping)
    content = json.loads(mapping.read_text(encoding="utf-8"))
    assert "10.20.30.40" in content["ip"]
