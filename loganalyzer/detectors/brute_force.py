"""Règle 1 – force brute SSH (MITRE ATT&CK T1110).

Détecte de nombreux échecs de mot de passe depuis la **même adresse IP** dans
une fenêtre de temps courte.

Choix de conception : on compte les lignes ``Failed password for <user>`` mais
**pas** ``Failed password for invalid user``. Ces dernières sont traitées par la
règle 2 (énumération de comptes) : ce sont deux signaux différents, et les
compter deux fois produirait un faux positif systématique.
"""

from __future__ import annotations

from ..helpers import extract_ip, group_by, sliding_window
from ..models import Alert, Config, Event

RULE = "ssh_brute_force"
MITRE = "T1110"
DESCRIPTION = "Échecs de mot de passe SSH répétés depuis une même IP."
RECOMMENDATION = (
    "Bloquer l'IP au niveau du pare-feu, vérifier qu'aucun compte n'a été "
    "compromis, et imposer l'authentification par clé."
)

_FAILED_RE = "Failed password for "


def _is_failed_password(event: Event) -> bool:
    """Vrai pour un échec de mot de passe sur un compte existant."""
    message = event.message
    return _FAILED_RE in message and "invalid user" not in message


def detect(events: list[Event], config: Config) -> list[Alert]:
    """Retourne une alerte par adresse IP qui dépasse le seuil."""
    candidates = [
        (ip, event)
        for event in events
        for ip in [extract_ip(event.message)]
        if ip and _is_failed_password(event)
    ]

    alerts: list[Alert] = []
    for ip, group in group_by(candidates).items():
        found = sliding_window(group, config.window_minutes, config.threshold)
        if found is None:
            continue
        start, end = found
        count = end - start + 1
        severity = "high" if count >= 2 * config.threshold else "medium"
        alerts.append(
            Alert(
                rule=RULE,
                severity=severity,
                timestamp=group[start].timestamp,
                message=(
                    f"{count} échecs de mot de passe SSH depuis {ip} "
                    f"en {config.window_minutes} minutes ou moins"
                ),
                evidence=group[end].message,
                recommendation=RECOMMENDATION,
                mitre=MITRE,
                count=count,
            )
        )
    return alerts
