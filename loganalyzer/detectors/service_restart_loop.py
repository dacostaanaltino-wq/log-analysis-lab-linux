"""Règle 6 – service qui redémarre en boucle (disponibilité).

Un service qui échoue puis redémarre sans fin est soit mal configuré, soit
attaqué (épuisement de mémoire, fichier supprimé). Dans les deux cas, il faut
le voir : c'est un problème de disponibilité et parfois un symptôme.

On compte les lignes ``Started <unité>.service`` par unité dans une fenêtre.
"""

from __future__ import annotations

import re

from ..helpers import group_by, sliding_window
from ..models import Alert, Config, Event

RULE = "service_restart_loop"
MITRE = ""
DESCRIPTION = "Service démarré plusieurs fois en peu de temps (boucle de redémarrage)."
RECOMMENDATION = (
    "Consulter journalctl -u <service> -n 50, corriger la cause (configuration, "
    "droits, mémoire) et poser une limite de redémarrage si nécessaire."
)

_STARTED_RE = re.compile(r"Started (?P<unit>[\w@.\-]+\.service)\.")


def _started_unit(event: Event) -> str | None:
    """Retourne le nom de l'unité démarrée, ou None."""
    match = _STARTED_RE.search(event.message)
    if match:
        return match.group("unit")
    if event.unit and event.message.startswith("Started "):
        return event.unit
    return None


def detect(events: list[Event], config: Config) -> list[Alert]:
    """Retourne une alerte par unité qui redémarre trop souvent."""
    candidates = [
        (unit, event)
        for event in events
        for unit in [_started_unit(event)]
        if unit
    ]

    alerts: list[Alert] = []
    for unit, group in group_by(candidates).items():
        found = sliding_window(group, config.window_minutes, config.restart_loop_count)
        if found is None:
            continue
        start, end = found
        count = end - start + 1
        alerts.append(
            Alert(
                rule=RULE,
                severity="medium" if count < 2 * config.restart_loop_count else "high",
                timestamp=group[start].timestamp,
                message=(
                    f"Le service {unit} a démarré {count} fois "
                    f"en {config.window_minutes} minutes ou moins"
                ),
                evidence=group[end].message,
                recommendation=RECOMMENDATION,
                mitre=MITRE,
                count=count,
            )
        )
    return alerts
