"""Règle 2 – énumération de comptes SSH (MITRE ATT&CK T1087).

Détecte beaucoup de **noms d'utilisateur différents** essayés depuis la même
adresse IP : c'est la signature d'un scan de comptes, qui précède souvent une
tentative de force brute ciblée.
"""

from __future__ import annotations

import re

from ..helpers import distinct_window, extract_ip
from ..models import Alert, Config, Event

RULE = "ssh_user_enumeration"
MITRE = "T1087"
DESCRIPTION = "Tentatives sur de nombreux noms de comptes différents depuis une même IP."
RECOMMENDATION = (
    "Bloquer l'IP, désactiver l'authentification par mot de passe et vérifier "
    "qu'aucun compte par défaut ne reste actif."
)

_INVALID_USER_RE = re.compile(r"Invalid user (?P<user>[A-Za-z0-9._@-]+) from")


def _invalid_user(event: Event) -> str | None:
    """Retourne le nom d'utilisateur inexistant essayé, ou None."""
    match = _INVALID_USER_RE.search(event.message)
    return match.group("user") if match else None


def detect(events: list[Event], config: Config) -> list[Alert]:
    """Retourne une alerte par IP qui essaie assez de comptes différents."""
    # On regroupe par IP : la valeur suivie est le nom d'utilisateur essayé.
    by_ip: dict[str, list[tuple[Event, str]]] = {}
    for event in events:
        ip = extract_ip(event.message)
        user = _invalid_user(event)
        if ip and user:
            by_ip.setdefault(ip, []).append((event, user))

    alerts: list[Alert] = []
    for ip, group in by_ip.items():
        found = distinct_window(group, config.window_minutes, config.min_invalid_users)
        if found is None:
            continue
        start, end, distinct = found
        alerts.append(
            Alert(
                rule=RULE,
                severity="medium",
                timestamp=group[start][0].timestamp,
                message=(
                    f"{distinct} noms de comptes différents essayés depuis {ip} "
                    f"en {config.window_minutes} minutes ou moins"
                ),
                evidence=group[end][0].message,
                recommendation=RECOMMENDATION,
                mitre=MITRE,
                count=distinct,
            )
        )
    return alerts
