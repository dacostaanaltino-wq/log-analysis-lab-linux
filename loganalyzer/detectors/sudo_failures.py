"""Règle 4 – échecs sudo répétés (MITRE ATT&CK T1548.003).

Deux signaux sont couverts :

* plusieurs mauvais mots de passe ``sudo`` pour le même utilisateur : soit une
  faute de frappe, soit une tentative d'escalade de privilèges ;
* une ligne ``user NOT in sudoers`` : quelqu'un a essayé d'utiliser ``sudo``
  sans en avoir le droit — un seul événement suffit à alerter.
"""

from __future__ import annotations

import re

from ..helpers import group_by, sliding_window
from ..models import Alert, Config, Event

RULE = "sudo_abuse"
MITRE = "T1548.003"
DESCRIPTION = "Échecs sudo répétés ou tentative de sudo sans autorisation."
RECOMMENDATION = (
    "Vérifier qui utilise le compte, contrôler /etc/sudoers, et ajouter une "
    "règle fail2ban ou auditd si la tentative est répétée."
)

_SUDO_USER_RE = re.compile(r"^(?P<user>[A-Za-z0-9._-]+) :")
_FAILURE_MARKERS = ("incorrect password attempt", "authentication failure")
_NOT_IN_SUDOERS = "NOT in sudoers"


def _sudo_user(event: Event) -> str | None:
    """Retourne l'utilisateur qui a lancé sudo, ou None."""
    match = _SUDO_USER_RE.match(event.message)
    return match.group("user") if match else None


def _is_sudo(event: Event) -> bool:
    """Vrai si l'événement vient du programme sudo."""
    return event.identifier == "sudo" or " : TTY=" in event.message


def detect(events: list[Event], config: Config) -> list[Alert]:
    """Retourne les alertes sudo (une par utilisateur qui dépasse le seuil)."""
    alerts: list[Alert] = []

    # 1. Tentatives sans droit : un seul événement suffit.
    for event in events:
        if _NOT_IN_SUDOERS in event.message:
            alerts.append(
                Alert(
                    rule=RULE,
                    severity="high",
                    timestamp=event.timestamp,
                    message=f"Tentative de sudo sans autorisation : {event.message[:120]}",
                    evidence=event.message,
                    recommendation=RECOMMENDATION,
                    mitre=MITRE,
                )
            )

    # 2. Échecs de mot de passe répétés.
    candidates: list[tuple[Event, str]] = []
    for event in events:
        if not _is_sudo(event):
            continue
        if not any(marker in event.message for marker in _FAILURE_MARKERS):
            continue
        user = _sudo_user(event)
        if user:
            candidates.append((user, event))

    for user, group in group_by(candidates).items():
        found = sliding_window(group, config.window_minutes, config.sudo_failures)
        if found is None:
            continue
        start, end = found
        alerts.append(
            Alert(
                rule=RULE,
                severity="medium",
                timestamp=group[start].timestamp,
                message=(
                    f"{end - start + 1} mots de passe sudo incorrects "
                    f"pour l'utilisateur « {user} »"
                ),
                evidence=group[end].message,
                recommendation=RECOMMENDATION,
                mitre=MITRE,
                count=end - start + 1,
            )
        )
    return alerts
