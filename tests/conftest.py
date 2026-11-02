"""Fixtures partagées par les tests.

La fonction ``make_event`` construit des événements en mémoire : les tests de
détection n'ont pas besoin de fichiers, ce qui les rend rapides et lisibles.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import pytest

from loganalyzer.models import Event

#: Instant de référence des tests (UTC, un mardi à 10 h).
BASE = datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc)


@pytest.fixture
def make_event() -> Callable[..., Event]:
    """Retourne une fabrique d'événements décalés par rapport à :data:`BASE`."""

    def _make(
        minutes: float = 0,
        message: str = "",
        identifier: str = "sshd",
        unit: str = "",
        priority: int = 6,
    ) -> Event:
        return Event(
            timestamp=BASE + timedelta(minutes=minutes),
            message=message,
            identifier=identifier,
            unit=unit,
            priority=priority,
        )

    return _make
