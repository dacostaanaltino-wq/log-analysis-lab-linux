"""loganalyzer – analyse de journaux systemd et détection d'événements suspects.

Bibliothèque standard uniquement (aucune dépendance externe) : ``json``,
``csv``, ``re``, ``datetime``, ``zoneinfo``, ``argparse``.

Utilisation en ligne de commande ::

    python -m loganalyzer analyze --input journal.jsonl --out reports/

Utilisation comme bibliothèque ::

    from loganalyzer import Config, load_events
    from loganalyzer.detectors import run_all
"""

from __future__ import annotations

from .models import Alert, Config, Event
from .parser import ParseError, iter_events, load_events

__all__ = [
    "Alert",
    "Config",
    "Event",
    "ParseError",
    "iter_events",
    "load_events",
]

__version__ = "1.0.0"
