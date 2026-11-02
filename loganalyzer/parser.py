"""Lecture des journaux au format ``journalctl -o json``.

Le format est simple : **un objet JSON par ligne** (JSON Lines). Chaque objet
contient des dizaines de champs ; on ne garde que ceux qui servent à la
détection, pour garder la mémoire raisonnable sur des journaux de plusieurs
centaines de milliers de lignes.

Exemple de ligne (tronquée) ::

    {"__REALTIME_TIMESTAMP":"1730451600123456","_HOSTNAME":"lab-vm",
     "SYSLOG_IDENTIFIER":"sshd","PRIORITY":"4",
     "MESSAGE":"Failed password for admin from 203.0.113.66 port 51234 ssh2"}
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from .models import Event


class ParseError(ValueError):
    """Ligne de journal illisible (JSON invalide ou horodatage absent)."""


def _to_timestamp(value: object) -> datetime:
    """Convertit ``__REALTIME_TIMESTAMP`` (microsecondes) en datetime UTC.

    ``journalctl`` écrit ce champ sous forme de chaîne, mais un fichier
    fabriqué à la main peut contenir un nombre : les deux sont acceptés.
    """
    if value is None:
        raise ParseError("champ __REALTIME_TIMESTAMP absent")
    try:
        micro = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ParseError(f"__REALTIME_TIMESTAMP invalide : {value!r}") from exc
    return datetime.fromtimestamp(micro / 1_000_000, tz=timezone.utc)


def _priority(value: object) -> int:
    """Retourne la priorité syslog, 6 (info) si la valeur est absente ou cassée."""
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 6


def parse_line(line: str) -> Event:
    """Transforme une ligne JSON en :class:`Event`.

    Lève :class:`ParseError` si la ligne n'est pas un objet JSON valide ou si
    l'horodatage manque : une ligne illisible ne doit jamais être ignorée en
    silence, sinon une alerte peut disparaître sans que personne ne le sache.
    """
    try:
        data = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ParseError(f"JSON invalide : {exc}") from exc
    if not isinstance(data, dict):
        raise ParseError("l'objet JSON n'est pas un dictionnaire")

    return Event(
        timestamp=_to_timestamp(data.get("__REALTIME_TIMESTAMP")),
        message=str(data.get("MESSAGE", "")),
        identifier=str(data.get("SYSLOG_IDENTIFIER", "")),
        unit=str(data.get("_SYSTEMD_UNIT", "")),
        hostname=str(data.get("_HOSTNAME", "")),
        priority=_priority(data.get("PRIORITY")),
    )


def iter_events(path: str | Path) -> Iterator[Event]:
    """Itère sur les événements d'un fichier, sans tout charger en mémoire."""
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(f"fichier introuvable : {source}")

    with source.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                yield parse_line(stripped)
            except ParseError as exc:
                raise ParseError(f"{source.name}, ligne {number} : {exc}") from exc


def load_events(path: str | Path) -> list[Event]:
    """Charge et trie les événements par horodatage croissant."""
    return sorted(iter_events(path), key=lambda event: event.timestamp)
