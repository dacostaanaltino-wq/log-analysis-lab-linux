"""Modèles de données du laboratoire d'analyse de journaux.

Trois objets suffisent pour tout l'outil :

* :class:`Event` – un événement tel que lu dans ``journalctl -o json`` ;
* :class:`Alert` – une alerte produite par une règle de détection ;
* :class:`Config` – les seuils configurables en ligne de commande.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

# Ordre de gravité, utilisé pour trier et filtrer les alertes.
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class Event:
    """Un événement de journal.

    Les champs correspondent aux clés JSON produites par ``journalctl -o json``.
    ``timestamp`` est toujours en UTC et conscient du fuseau (timezone-aware) :
    c'est ce qui rend les calculs de fenêtres fiables.
    """

    timestamp: datetime
    message: str
    identifier: str = ""  # SYSLOG_IDENTIFIER (sshd, sudo, systemd, ...)
    unit: str = ""  # _SYSTEMD_UNIT
    hostname: str = ""  # _HOSTNAME
    priority: int = 6  # PRIORITY (6 = info)

    @property
    def is_error(self) -> bool:
        """Vrai si la priorité syslog est err (3) ou plus grave."""
        return self.priority <= 3


@dataclass(frozen=True)
class Alert:
    """Une alerte : une preuve, une règle, une recommandation."""

    rule: str
    severity: str  # "low", "medium", "high"
    timestamp: datetime
    message: str
    evidence: str  # la ligne de journal qui justifie l'alerte
    recommendation: str = ""
    mitre: str = ""  # identifiant MITRE ATT&CK, ex. T1110
    count: int = 1  # nombre d'événements regroupés

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(
                f"sévérité inconnue : {self.severity!r} "
                f"(attendu : {', '.join(SEVERITY_ORDER)})"
            )

    @property
    def severity_rank(self) -> int:
        """Rang numérique de la sévérité (1 = low, 3 = high)."""
        return SEVERITY_ORDER[self.severity]


@dataclass
class Config:
    """Seuils de détection.

    Les valeurs par défaut correspondent au jeu de données synthétique de
    ``data/sample`` et sont documentées dans ``docs/rules.md``.
    """

    window_minutes: int = 10
    threshold: int = 5

    # Règle 1 – brute force : nombre d'échecs pour dépasser le seuil.
    # (utilise `threshold` et `window_minutes`)

    # Règle 2 – énumération de comptes.
    min_invalid_users: int = 5

    # Règle 3 – succès après échecs.
    failures_before_success: int = 4

    # Règle 4 – échecs sudo.
    sudo_failures: int = 3

    # Règle 6 – service qui redémarre en boucle.
    restart_loop_count: int = 3

    # Règle 8 – heures inhabituelles.
    business_hours: tuple[int, int] = (8, 19)  # [début, fin) en heures locales
    timezone_name: str = "UTC"

    # Filtres optionnels.
    enabled_rules: set[str] = field(default_factory=set)

    def is_enabled(self, rule: str) -> bool:
        """Vrai si la règle doit tourner (ensemble vide = toutes)."""
        return not self.enabled_rules or rule in self.enabled_rules
