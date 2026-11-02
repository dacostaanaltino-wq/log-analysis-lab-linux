"""Interface en ligne de commande.

Exemple ::

    python -m loganalyzer analyze \\
        --input data/sample/synthetic-3days.jsonl \\
        --window 10 --threshold 5 --out reports/
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .detectors import RULES, run_all
from .models import Config
from .parser import ParseError, load_events
from .report import severity_counts, write_reports

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_ALERTS = 3

_SEVERITY_TO_RANK = {"low": 1, "medium": 2, "high": 3}


def _business_hours(text: str) -> tuple[int, int]:
    """Convertit ``"8-19"`` en ``(8, 19)``.

    Utilisé comme ``type=`` d'argparse : une valeur invalide doit produire un
    message clair, pas une exception Python.
    """
    try:
        start_text, end_text = text.split("-", 1)
        start, end = int(start_text), int(end_text)
    except (ValueError, AttributeError) as exc:
        raise argparse.ArgumentTypeError(
            f"format attendu « début-fin » en heures, ex. 8-19 (reçu : {text!r})"
        ) from exc
    if not (0 <= start < 24 and 0 <= end <= 24 and start < end):
        raise argparse.ArgumentTypeError(
            f"plage invalide : {text!r} (0 <= début < fin <= 24)"
        )
    return start, end


def _positive_int(text: str) -> int:
    """Convertit en entier strictement positif."""
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"entier attendu (reçu : {text!r})") from exc
    if value <= 0:
        raise argparse.ArgumentTypeError(f"valeur positive attendue (reçu : {value})")
    return value


def build_parser() -> argparse.ArgumentParser:
    """Construit l'analyseur d'arguments (séparé de ``main`` pour les tests)."""
    parser = argparse.ArgumentParser(
        prog="python -m loganalyzer",
        description=(
            "Analyse de journaux systemd au format « journalctl -o json » "
            "et détection d'événements suspects."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser(
        "analyze",
        help="Analyse un fichier de journal et écrit un rapport.",
        description="Analyse un fichier JSON Lines et produit report.md + findings.csv.",
    )
    analyze.add_argument(
        "--input",
        required=True,
        metavar="FICHIER",
        help="Journal à analyser (une ligne JSON par événement).",
    )
    analyze.add_argument(
        "--out",
        default="reports",
        metavar="DOSSIER",
        help="Dossier de sortie (défaut : reports/).",
    )
    analyze.add_argument(
        "--window",
        type=_positive_int,
        default=10,
        metavar="MINUTES",
        help="Taille de la fenêtre d'observation en minutes (défaut : 10).",
    )
    analyze.add_argument(
        "--threshold",
        type=_positive_int,
        default=5,
        metavar="N",
        help="Nombre d'échecs pour la règle brute force (défaut : 5).",
    )
    analyze.add_argument(
        "--min-invalid-users",
        type=_positive_int,
        default=5,
        metavar="N",
        help="Comptes distincts pour la règle d'énumération (défaut : 5).",
    )
    analyze.add_argument(
        "--failures-before-success",
        type=_positive_int,
        default=4,
        metavar="N",
        help="Échecs avant un succès suspect (défaut : 4).",
    )
    analyze.add_argument(
        "--sudo-failures",
        type=_positive_int,
        default=3,
        metavar="N",
        help="Échecs sudo pour alerter (défaut : 3).",
    )
    analyze.add_argument(
        "--restart-loop",
        type=_positive_int,
        default=3,
        metavar="N",
        help="Démarrages d'un service pour alerter (défaut : 3).",
    )
    analyze.add_argument(
        "--business-hours",
        type=_business_hours,
        default=(8, 19),
        metavar="DEBUT-FIN",
        help="Plage d'horaires normaux, ex. 8-19 (défaut : 8-19).",
    )
    analyze.add_argument(
        "--tz",
        default="UTC",
        metavar="FUSEAU",
        help="Fuseau horaire pour la règle des horaires, ex. Europe/Paris (défaut : UTC).",
    )
    analyze.add_argument(
        "--rules",
        default="",
        metavar="LISTE",
        help="Règles à exécuter, séparées par des virgules (défaut : toutes).",
    )
    analyze.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high"),
        default="none",
        help=(
            "Code de retour 3 si une alerte atteint ce niveau "
            "(pratique pour la CI ; défaut : none)."
        ),
    )
    analyze.add_argument(
        "--quiet",
        action="store_true",
        help="N'affiche que le chemin des fichiers produits.",
    )
    return parser


def _config_from_args(args: argparse.Namespace) -> Config:
    """Traduit les arguments en :class:`Config`."""
    selected: set[str] = set()
    if args.rules:
        selected = {name.strip() for name in args.rules.split(",") if name.strip()}
        unknown = selected - set(RULES)
        if unknown:
            raise ValueError(
                f"règle(s) inconnue(s) : {', '.join(sorted(unknown))}. "
                f"Règles disponibles : {', '.join(sorted(RULES))}"
            )

    return Config(
        window_minutes=args.window,
        threshold=args.threshold,
        min_invalid_users=args.min_invalid_users,
        failures_before_success=args.failures_before_success,
        sudo_failures=args.sudo_failures,
        restart_loop_count=args.restart_loop,
        business_hours=args.business_hours,
        timezone_name=args.tz,
        enabled_rules=selected,
    )


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée. Retourne le code de sortie du programme."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "analyze":  # pragma: no cover - argparse limite déjà les choix
        parser.error(f"commande inconnue : {args.command}")
        return EXIT_USAGE

    try:
        config = _config_from_args(args)
    except ValueError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        events = load_events(args.input)
    except FileNotFoundError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return EXIT_USAGE
    except ParseError as exc:
        print(f"Erreur de lecture du journal : {exc}", file=sys.stderr)
        return EXIT_USAGE

    alerts = run_all(events, config)
    report_path, csv_path = write_reports(events, alerts, args.input, config, args.out)

    if args.quiet:
        print(report_path)
        print(csv_path)
    else:
        counts = severity_counts(alerts)
        print(f"Événements analysés : {len(events)}")
        print(f"Alertes : {len(alerts)} "
              f"(élevées : {counts['high']}, moyennes : {counts['medium']}, faibles : {counts['low']})")
        print(f"Rapport : {report_path}")
        print(f"CSV     : {csv_path}")

    if args.fail_on != "none":
        limit = _SEVERITY_TO_RANK[args.fail_on]
        if any(alert.severity_rank >= limit for alert in alerts):
            return EXIT_ALERTS
    return EXIT_OK
