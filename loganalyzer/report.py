"""Génération du rapport : ``report.md`` (lisible) et ``findings.csv`` (triable).

Le rapport Markdown est fait pour être lu et publié ; le CSV est fait pour être
ouvert dans un tableur ou rechargé par un autre outil.
"""

from __future__ import annotations

import csv
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .detectors import RULES
from .models import SEVERITY_ORDER, Alert, Config, Event

CSV_COLUMNS = [
    "timestamp_utc",
    "severity",
    "rule",
    "mitre",
    "count",
    "message",
    "evidence",
    "recommendation",
]

_SEVERITY_LABELS = {"high": "ÉLEVÉE", "medium": "MOYENNE", "low": "FAIBLE"}


def _format_time(moment: datetime) -> str:
    """Formate un horodatage en UTC, à la seconde."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _short(text: str, limit: int = 110) -> str:
    """Tronque un texte et échappe les barres verticales du tableau Markdown."""
    clean = text.replace("|", "\\|").replace("\n", " ").strip()
    if len(clean) <= limit:
        return clean
    return clean[: limit - 1] + "…"


def build_report(
    events: list[Event],
    alerts: list[Alert],
    source: str,
    config: Config,
) -> str:
    """Construit le contenu Markdown du rapport."""
    lines: list[str] = []
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines.append("# Rapport d'analyse de journaux")
    lines.append("")
    lines.append(f"- **Source** : `{Path(source).name}`")
    lines.append(f"- **Événements analysés** : {len(events)}")
    if events:
        first, last = events[0].timestamp, events[-1].timestamp
        lines.append(f"- **Période couverte** : {_format_time(first)} → {_format_time(last)} (UTC)")
    lines.append(f"- **Fenêtre de détection** : {config.window_minutes} minutes")
    lines.append(f"- **Seuil d'échecs (brute force)** : {config.threshold}")
    lines.append(f"- **Horaires de travail** : {config.business_hours[0]}h–{config.business_hours[1]}h ({config.timezone_name})")
    lines.append(f"- **Rapport généré le** : {now}")
    lines.append("")

    # --- Résumé -----------------------------------------------------------
    counts = Counter(alert.severity for alert in alerts)
    lines.append("## Résumé")
    lines.append("")
    lines.append("| Sévérité | Nombre d'alertes |")
    lines.append("|---|---|")
    for severity in ("high", "medium", "low"):
        lines.append(f"| {_SEVERITY_LABELS[severity]} | {counts.get(severity, 0)} |")
    lines.append(f"| **Total** | **{len(alerts)}** |")
    lines.append("")

    if not alerts:
        lines.append("Aucune alerte : aucun comportement correspondant aux règles n'a été trouvé.")
        lines.append("")
        lines.append("Attention : l'absence d'alerte ne prouve pas l'absence d'attaque. "
                     "Voir la section « Limites » de `docs/rules.md`.")
        return "\n".join(lines) + "\n"

    # --- Alertes ----------------------------------------------------------
    lines.append("## Alertes")
    lines.append("")
    lines.append("| # | Horodatage (UTC) | Sévérité | Règle | MITRE | Détail | Preuve (ligne de journal) |")
    lines.append("|---|---|---|---|---|---|---|")
    for index, alert in enumerate(alerts, start=1):
        lines.append(
            f"| {index} | {_format_time(alert.timestamp)} | "
            f"{_SEVERITY_LABELS[alert.severity]} | `{alert.rule}` | "
            f"{alert.mitre or '—'} | {_short(alert.message, 90)} | "
            f"`{_short(alert.evidence, 110)}` |"
        )
    lines.append("")

    # --- Recommandations --------------------------------------------------
    lines.append("## Recommandations")
    lines.append("")
    by_rule = Counter(alert.rule for alert in alerts)
    for rule, count in sorted(by_rule.items(), key=lambda item: (-item[1], item[0])):
        module = RULES.get(rule)
        description = module.DESCRIPTION if module else ""
        recommendation = module.RECOMMENDATION if module else ""
        lines.append(f"### `{rule}` — {count} alerte(s)")
        lines.append("")
        lines.append(f"{description}")
        lines.append("")
        lines.append(f"**À faire** : {recommendation}")
        lines.append("")

    # --- Méthode ----------------------------------------------------------
    lines.append("## Comment lire ce rapport")
    lines.append("")
    lines.append("- Les heures sont en **UTC** (sauf mention contraire).")
    lines.append("- Chaque alerte cite **la ligne de journal** qui la justifie : c'est la preuve.")
    lines.append("- Une alerte n'est pas une preuve d'attaque : c'est un point à vérifier.")
    lines.append("- Ordre de tri : sévérité décroissante, puis horodatage croissant.")
    lines.append("")
    lines.append("Sévérités : **ÉLEVÉE** = action immédiate, **MOYENNE** = à vérifier "
                 "dans la journée, **FAIBLE** = contexte à confronter.")
    lines.append("")
    return "\n".join(lines) + "\n"


def write_csv(alerts: list[Alert], path: str | Path) -> Path:
    """Écrit les alertes en CSV (UTF-8, séparateur virgule)."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for alert in alerts:
            writer.writerow(
                {
                    "timestamp_utc": _format_time(alert.timestamp),
                    "severity": alert.severity,
                    "rule": alert.rule,
                    "mitre": alert.mitre,
                    "count": alert.count,
                    "message": alert.message,
                    "evidence": alert.evidence,
                    "recommendation": alert.recommendation,
                }
            )
    return destination


def write_reports(
    events: list[Event],
    alerts: list[Alert],
    source: str,
    config: Config,
    out_dir: str | Path,
) -> tuple[Path, Path]:
    """Écrit ``report.md`` et ``findings.csv`` dans ``out_dir``."""
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)

    report_path = directory / "report.md"
    report_path.write_text(build_report(events, alerts, source, config), encoding="utf-8")

    csv_path = write_csv(alerts, directory / "findings.csv")
    return report_path, csv_path


def severity_counts(alerts: list[Alert]) -> dict[str, int]:
    """Compte les alertes par sévérité (toutes les clés sont présentes)."""
    counts = Counter(alert.severity for alert in alerts)
    return {severity: counts.get(severity, 0) for severity in SEVERITY_ORDER}
