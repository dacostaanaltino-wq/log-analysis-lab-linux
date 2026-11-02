"""Petites fonctions partagées par les règles de détection.

Elles sont volontairement simples et sans dépendance : une fenêtre glissante
se code en quelques lignes, inutile d'ajouter une bibliothèque.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from datetime import timedelta

from .models import Event

# Une adresse IPv4 : quatre nombres de 0 à 255 séparés par des points.
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# « for alice from 203.0.113.9 » ou « invalid user alice from 203.0.113.9 »
USER_FROM_RE = re.compile(r"(?:for|user)\s+(?P<user>[A-Za-z0-9._@-]+)\s+from\s+(?P<ip>\S+)")


def extract_ip(message: str) -> str | None:
    """Retourne la première adresse IPv4 du message, ou None."""
    match = IPV4_RE.search(message)
    return match.group(0) if match else None


def extract_user(message: str) -> str | None:
    """Retourne le nom d'utilisateur cité dans le message, ou None."""
    match = USER_FROM_RE.search(message)
    if match:
        return match.group("user")
    return None


def sliding_window(
    events: Sequence[Event],
    window_minutes: int,
    threshold: int,
) -> tuple[int, int] | None:
    """Cherche la fenêtre la plus dense, si elle dépasse ``threshold``.

    Les événements doivent être triés. Retourne ``(début, fin)`` : les indices
    du premier et du dernier événement de la fenêtre la plus chargée, ou
    ``None`` si même la fenêtre la plus dense reste sous le seuil.

    On retourne la fenêtre **la plus dense** et non la première qui atteint le
    seuil : le rapport doit dire « 12 échecs en 6 minutes », pas « 5 échecs ».

    C'est l'algorithme à deux pointeurs classique : O(n) en temps, sans
    relecture des événements.
    """
    if threshold <= 0 or len(events) < threshold:
        return None

    window = timedelta(minutes=window_minutes)
    start = 0
    best_count = 0
    best: tuple[int, int] | None = None

    for end, event in enumerate(events):
        # On avance le début tant que la fenêtre est trop large.
        while event.timestamp - events[start].timestamp > window:
            start += 1
        count = end - start + 1
        if count > best_count:
            best_count = count
            best = (start, end)

    return best if best_count >= threshold else None


def distinct_window(
    items: Sequence[tuple[Event, str]],
    window_minutes: int,
    threshold: int,
) -> tuple[int, int, int] | None:
    """Cherche la fenêtre contenant le plus de valeurs distinctes.

    ``items`` est une séquence de ``(événement, valeur)`` triée par temps.
    Utilisé pour l'énumération de comptes : plusieurs noms d'utilisateur
    différents depuis la même adresse en peu de temps.

    Retourne ``(début, fin, nombre_de_valeurs_distinctes)`` pour la fenêtre la
    plus riche, ou ``None`` si elle reste sous ``threshold``.
    """
    if threshold <= 0:
        return None

    window = timedelta(minutes=window_minutes)
    start = 0
    counts: dict[str, int] = {}
    best: tuple[int, int, int] | None = None

    for end, (event, value) in enumerate(items):
        while event.timestamp - items[start][0].timestamp > window:
            old = items[start][1]
            counts[old] -= 1
            if counts[old] == 0:
                del counts[old]
            start += 1
        counts[value] = counts.get(value, 0) + 1
        distinct = len(counts)
        if best is None or distinct > best[2]:
            best = (start, end, distinct)

    if best is None or best[2] < threshold:
        return None
    return best


def group_by(items: Iterable[tuple[str, Event]]) -> dict[str, list[Event]]:
    """Regroupe des événements par clé en conservant l'ordre d'arrivée."""
    groups: dict[str, list[Event]] = {}
    for key, event in items:
        groups.setdefault(key, []).append(event)
    return groups
