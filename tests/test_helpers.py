"""Tests des utilitaires : fenêtre glissante, extraction, regroupement."""

from __future__ import annotations

from collections.abc import Callable

from loganalyzer.helpers import (
    distinct_window,
    extract_ip,
    extract_user,
    group_by,
    sliding_window,
)
from loganalyzer.models import Event


def test_extract_ip_trouve_la_premiere_adresse() -> None:
    message = "Failed password for admin from 203.0.113.66 port 51234 ssh2"
    assert extract_ip(message) == "203.0.113.66"


def test_extract_ip_retourne_none_sans_adresse() -> None:
    assert extract_ip("Started chronyd.service") is None


def test_extract_user_lit_le_nom_apres_for() -> None:
    message = "Accepted publickey for labuser from 192.0.2.10 port 40000 ssh2"
    assert extract_user(message) == "labuser"


def test_sliding_window_detecte_le_seuil(make_event: Callable[..., Event]) -> None:
    events = [make_event(minutes=index) for index in range(5)]
    found = sliding_window(events, window_minutes=10, threshold=5)
    assert found is not None
    start, end = found
    assert (start, end) == (0, 4)


def test_sliding_window_retourne_la_fenetre_la_plus_dense(
    make_event: Callable[..., Event],
) -> None:
    # 3 événements au début, 6 ensuite : la fenêtre la plus dense est la seconde.
    events = [make_event(minutes=index) for index in range(3)]
    events += [make_event(minutes=20 + index) for index in range(6)]
    found = sliding_window(events, window_minutes=10, threshold=5)
    assert found is not None
    start, end = found
    assert end - start + 1 == 6


def test_sliding_window_respecte_la_duree(make_event: Callable[..., Event]) -> None:
    # 5 événements espacés de 5 minutes : jamais 5 dans 10 minutes.
    events = [make_event(minutes=5 * index) for index in range(5)]
    assert sliding_window(events, window_minutes=10, threshold=5) is None


def test_sliding_window_sous_le_seuil(make_event: Callable[..., Event]) -> None:
    events = [make_event(minutes=index) for index in range(4)]
    assert sliding_window(events, window_minutes=10, threshold=5) is None


def test_sliding_window_liste_vide(make_event: Callable[..., Event]) -> None:
    assert sliding_window([], window_minutes=10, threshold=3) is None


def test_distinct_window_compte_les_valeurs_distinctes(
    make_event: Callable[..., Event],
) -> None:
    items = [(make_event(minutes=index), f"utilisateur-{index % 5}") for index in range(8)]
    found = distinct_window(items, window_minutes=10, threshold=5)
    assert found is not None
    assert found[2] == 5


def test_distinct_window_ne_compte_qu_une_fois_la_meme_valeur(
    make_event: Callable[..., Event],
) -> None:
    items = [(make_event(minutes=index), "meme-utilisateur") for index in range(10)]
    assert distinct_window(items, window_minutes=10, threshold=5) is None


def test_group_by_conserve_la_cle_et_l_ordre(make_event: Callable[..., Event]) -> None:
    a = make_event(minutes=0, message="a")
    b = make_event(minutes=1, message="b")
    grouped = group_by([("cle1", a), ("cle2", b), ("cle1", b)])
    assert list(grouped) == ["cle1", "cle2"]
    assert grouped["cle1"] == [a, b]
