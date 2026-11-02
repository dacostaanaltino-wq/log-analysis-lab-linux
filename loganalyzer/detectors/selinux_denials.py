"""Règle 7 – refus SELinux regroupés par processus.

Les lignes ``avc: denied`` ne sont pas des alertes de sécurité à elles seules :
elles indiquent surtout un problème de contexte ou d'étiquette. Mais un
processus **inhabituel** (par exemple ``comm="nc"``) qui se fait refuser un
accès est intéressant : c'est un poste d'observation privilégié sur ce que le
système empêche réellement.
"""

from __future__ import annotations

import re

from ..helpers import group_by
from ..models import Alert, Config, Event

RULE = "selinux_denied"
MITRE = ""
DESCRIPTION = "Refus SELinux (avc: denied) regroupés par processus."
RECOMMENDATION = (
    "Lire le refus avec ausearch -m AVC -ts recent, puis corriger l'étiquette "
    "(restorecon/semanage) au lieu de passer SELinux en permissive."
)

_COMM_RE = re.compile(r'comm="(?P<comm>[^"]+)"')
_DENIED_RE = re.compile(r"avc:\s+denied")


def _denied_comm(event: Event) -> str | None:
    """Retourne le nom du processus refusé, ou None."""
    if not _DENIED_RE.search(event.message):
        return None
    match = _COMM_RE.search(event.message)
    return match.group("comm") if match else "inconnu"


def detect(events: list[Event], config: Config) -> list[Alert]:
    """Retourne une alerte par processus refusé par SELinux."""
    candidates = [
        (comm, event)
        for event in events
        for comm in [_denied_comm(event)]
        if comm
    ]

    alerts: list[Alert] = []
    for comm, group in group_by(candidates).items():
        count = len(group)
        alerts.append(
            Alert(
                rule=RULE,
                severity="low" if count < 3 else "medium",
                timestamp=group[0].timestamp,
                message=f"{count} refus SELinux pour le processus « {comm} »",
                evidence=group[-1].message,
                recommendation=RECOMMENDATION,
                mitre=MITRE,
                count=count,
            )
        )
    return alerts
