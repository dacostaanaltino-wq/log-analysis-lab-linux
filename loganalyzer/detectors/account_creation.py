"""Règle 5 – création de compte ou ajout au groupe wheel (MITRE ATT&CK T1136).

Une création de compte n'est pas toujours malveillante (un administrateur peut
en créer un). Mais **hors d'une fenêtre de maintenance**, c'est un signe de
persistance : l'attaquant s'assure un accès durable.

La règle est volontairement « bavarde » : elle alerte à chaque événement, et
c'est l'analyste qui décide si c'est légitime. Le rapport indique clairement la
recommandation : vérifier auprès de l'équipe.
"""

from __future__ import annotations

import re

from ..models import Alert, Config, Event

RULE = "account_creation"
MITRE = "T1136"
DESCRIPTION = "Création de compte ou modification de groupe privilégié."
RECOMMENDATION = (
    "Vérifier que la création est autorisée (ticket, fenêtre de maintenance). "
    "Si non : supprimer le compte, révoquer ses clés et chercher la persistance."
)

# Programmes qui créent ou modifient des comptes.
_TOOL_IDENTIFIERS = {
    "useradd",
    "adduser",
    "usermod",
    "groupadd",
    "gpasswd",
    "userdel",
}

_ADD_TO_GROUP_RE = re.compile(r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'")
_NEW_USER_RE = re.compile(r"new user: name=(?P<user>[A-Za-z0-9._-]+)")
# Ligne d'auditd issue de nos règles (voir projet linux-hardening-lab-fedora).
_AUDIT_USER_CHANGE = "key=\"user_change\""


def _reason(event: Event) -> str | None:
    """Retourne la description de la modification, ou None si non concerné."""
    match = _ADD_TO_GROUP_RE.search(event.message)
    if match:
        return (
            f"Utilisateur « {match.group('user')} » ajouté au groupe "
            f"« {match.group('group')} »"
        )

    match = _NEW_USER_RE.search(event.message)
    if match:
        return f"Nouveau compte créé : « {match.group('user')} »"

    if _AUDIT_USER_CHANGE in event.message:
        return "Commande de gestion de comptes exécutée (auditd)"

    if event.identifier in _TOOL_IDENTIFIERS and event.message.strip():
        return f"Outil de gestion de comptes : {event.identifier} – {event.message[:100]}"

    return None


def detect(events: list[Event], config: Config) -> list[Alert]:
    """Retourne une alerte par événement de gestion de compte détecté."""
    alerts: list[Alert] = []
    for event in events:
        reason = _reason(event)
        if reason is None:
            continue

        # Un ajout au groupe wheel (ou sudo) est plus grave qu'une simple création.
        severity = "high" if "wheel" in event.message or "sudo" in event.message else "medium"
        alerts.append(
            Alert(
                rule=RULE,
                severity=severity,
                timestamp=event.timestamp,
                message=reason,
                evidence=event.message,
                recommendation=RECOMMENDATION,
                mitre=MITRE,
            )
        )
    return alerts
