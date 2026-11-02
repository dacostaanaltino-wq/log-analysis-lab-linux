"""Règle 8 – connexions réussies à des heures inhabituelles.

Une connexion à 3 h du matin n'est pas une preuve d'attaque : c'est un signal
faible, à confronter au contexte (astreinte, autre fuseau horaire). D'où la
sévérité ``low``.

La plage horaire est configurable : ``--business-hours 8-19`` et
``--tz Europe/Paris`` (conversion via ``zoneinfo``, bibliothèque standard).
"""

from __future__ import annotations

import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ..models import Alert, Config, Event

RULE = "login_unusual_hours"
MITRE = ""
DESCRIPTION = "Connexion réussie en dehors des horaires de travail définis."
RECOMMENDATION = (
    "Vérifier avec l'utilisateur que la connexion est légitime (astreinte, "
    "déplacement) ; sinon, considérer le compte comme compromis."
)

_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/\S+) for (?P<user>[^ ]+) from"
)


def detect(events: list[Event], config: Config) -> list[Alert]:
    """Retourne une alerte par connexion réussie hors horaires."""
    try:
        tzinfo = ZoneInfo(config.timezone_name)
    except ZoneInfoNotFoundError:
        # Fuseau inconnu : on garde l'UTC plutôt que de planter l'analyse.
        tzinfo = ZoneInfo("UTC")

    start_hour, end_hour = config.business_hours
    alerts: list[Alert] = []

    for event in events:
        match = _ACCEPTED_RE.search(event.message)
        if not match:
            continue
        local_hour = event.timestamp.astimezone(tzinfo).hour
        if start_hour <= local_hour < end_hour:
            continue
        alerts.append(
            Alert(
                rule=RULE,
                severity="low",
                timestamp=event.timestamp,
                message=(
                    f"Connexion réussie de « {match.group('user')} » à "
                    f"{event.timestamp.astimezone(tzinfo).strftime('%H:%M')} "
                    f"({config.timezone_name}), hors plage "
                    f"{start_hour}h–{end_hour}h"
                ),
                evidence=event.message,
                recommendation=RECOMMENDATION,
                mitre=MITRE,
            )
        )
    return alerts
