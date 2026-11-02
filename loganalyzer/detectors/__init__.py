"""Registre des règles de détection.

Chaque module expose la même interface ::

    RULE           identifiantstable de la règle (utilisé dans le rapport)
    MITRE          identifiant MITRE ATT&CK (chaîne vide si non applicable)
    DESCRIPTION    phrase courte affichée dans le rapport
    RECOMMENDATION ce qu'il faut faire quand l'alerte se déclenche
    detect(events, config) -> list[Alert]

Ajouter une règle = créer un module, l'importer ici et l'ajouter à
``DETECTORS``. Aucun autre fichier n'a besoin d'être modifié.
"""

from __future__ import annotations

from ..models import Alert, Config, Event
from . import (
    account_creation,
    brute_force,
    selinux_denials,
    service_restart_loop,
    success_after_failures,
    sudo_failures,
    unusual_hours,
    user_enumeration,
)

# L'ordre n'a pas d'importance pour le résultat : les alertes sont triées
# à la fin, par sévérité puis par horodatage.
DETECTORS = (
    brute_force,
    user_enumeration,
    success_after_failures,
    sudo_failures,
    account_creation,
    service_restart_loop,
    selinux_denials,
    unusual_hours,
)

#: Règles disponibles : identifiant -> module.
RULES = {module.RULE: module for module in DETECTORS}


def run_all(events: list[Event], config: Config) -> list[Alert]:
    """Exécute toutes les règles activées et retourne les alertes triées.

    Tri : sévérité décroissante, puis horodatage croissant. Un rapport se lit
    toujours du plus grave au moins grave.
    """
    alerts: list[Alert] = []
    for module in DETECTORS:
        if not config.is_enabled(module.RULE):
            continue
        alerts.extend(module.detect(events, config))

    alerts.sort(key=lambda alert: (-alert.severity_rank, alert.timestamp))
    return alerts
