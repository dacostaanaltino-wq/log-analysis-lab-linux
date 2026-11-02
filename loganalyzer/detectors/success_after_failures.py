"""Règle 3 – connexion réussie après plusieurs échecs (MITRE ATT&CK T1078).

C'est l'indicateur le plus important du lot : quelqu'un a fini par trouver un
mot de passe valide. Sur un vrai système, cela déclenche une investigation
immédiate (le compte doit être considéré comme compromis jusqu'à preuve du
contraire).
"""

from __future__ import annotations

import re
from datetime import timedelta

from ..helpers import extract_ip, group_by
from ..models import Alert, Config, Event

RULE = "ssh_success_after_failures"
MITRE = "T1078"
DESCRIPTION = "Connexion SSH réussie après plusieurs échecs depuis la même IP."
RECOMMENDATION = (
    "Traiter le compte comme compromis : changer le mot de passe, révoquer les "
    "clés, relire les commandes exécutées (auditd) et chercher la persistance."
)

_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/\S+) for (?P<user>[A-Za-z0-9._@-]+) from"
)
_FAILURE_MARKERS = ("Failed password for", "Invalid user")


def _is_failure(event: Event) -> bool:
    """Vrai si la ligne signale un échec d'authentification SSH."""
    return any(marker in event.message for marker in _FAILURE_MARKERS)


def _is_success(event: Event) -> bool:
    """Vrai si la ligne signale une authentification SSH réussie."""
    return bool(_ACCEPTED_RE.search(event.message))


def detect(events: list[Event], config: Config) -> list[Alert]:
    """Alerte si un succès suit assez d'échecs de la même IP."""
    candidates = [
        (ip, event)
        for event in events
        for ip in [extract_ip(event.message)]
        if ip and (_is_failure(event) or _is_success(event))
    ]

    alerts: list[Alert] = []
    window = timedelta(minutes=config.window_minutes)

    for ip, group in group_by(candidates).items():
        # Échecs en attente dans la fenêtre courante (parcours chronologique).
        recent_failures: list[Event] = []
        for event in group:
            # On oublie les échecs trop anciens avant tout contrôle : sinon un
            # succès intervenu 40 minutes plus tard serait compté à tort.
            recent_failures = [
                failure
                for failure in recent_failures
                if event.timestamp - failure.timestamp <= window
            ]
            if _is_failure(event):
                recent_failures.append(event)
                continue
            if _is_success(event) and len(recent_failures) >= config.failures_before_success:
                user = _ACCEPTED_RE.search(event.message)
                alerts.append(
                    Alert(
                        rule=RULE,
                        severity="high",
                        timestamp=event.timestamp,
                        message=(
                            f"Connexion réussie pour "
                            f"« {user.group('user') if user else '?'} » depuis {ip} "
                            f"après {len(recent_failures)} échecs"
                        ),
                        evidence=event.message,
                        recommendation=RECOMMENDATION,
                        mitre=MITRE,
                        count=len(recent_failures),
                    )
                )
                # On repart de zéro : un seul succès anormal par IP.
                recent_failures = []
    return alerts
