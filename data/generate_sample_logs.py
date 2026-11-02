#!/usr/bin/env python3
"""Génère un jeu de journaux SYNTHÉTIQUE au format ``journalctl -o json``.

Pourquoi un jeu synthétique ? Parce qu'on ne peut pas publier de vrais journaux
(ils contiennent des adresses IP, des noms d'utilisateur, des noms de machine).
Ici, tout est fabriqué : les adresses IP appartiennent aux plages réservées à la
documentation (RFC 5737 : 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) et les
noms sont fictifs.

Le générateur est **déterministe** (graine fixe) : deux exécutions produisent le
même fichier, ce qui rend les tests fiables.

Usage :
    python3 data/generate_sample_logs.py
    python3 data/generate_sample_logs.py --out-dir /tmp/lab --days 3 --seed 42

Sorties :
    <out-dir>/synthetic-3days.jsonl     les journaux (une ligne JSON par événement)
    <out-dir>/expected_incidents.json   les incidents injectés et le nombre
                                        d'alertes attendu par règle
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

# --------------------------------------------------------------------------
# Constantes du scénario
# --------------------------------------------------------------------------

#: Début du jeu de données (UTC). Choisi un mardi, hors week-end.
START = datetime(2026, 10, 27, 0, 0, tzinfo=timezone.utc)

#: Nom de machine fictif (jamais le vrai nom de ma VM).
HOSTNAME = "lab-vm"

#: Adresses IP réservées à la documentation (RFC 5737) et plage de lab.
IP_ADMIN = "192.0.2.10"  # poste d'administration (connexions normales)
IP_BRUTEFORCE = "203.0.113.66"  # scénario 1
IP_ENUM = "198.51.100.23"  # scénario 2
IP_COMPROMISE = "203.0.113.77"  # scénario 3

#: Paramètres attendus par défaut de l'analyseur (voir data/ground-truth.md).
DEFAULT_PARAMETERS = {
    "window_minutes": 10,
    "threshold": 5,
    "min_invalid_users": 5,
    "failures_before_success": 4,
    "sudo_failures": 3,
    "restart_loop_count": 3,
    "business_hours": [8, 19],
    "timezone_name": "UTC",
}


def _microseconds(moment: datetime) -> str:
    """Convertit un datetime en microsecondes depuis l'époque UNIX (format journald)."""
    return str(int(moment.timestamp() * 1_000_000))


class JournalBuilder:
    """Petit constructeur d'événements de journal.

    Il garde la liste des incidents injectés : c'est cette liste qui devient le
    « ground truth » (la vérité terrain) du jeu de données.
    """

    def __init__(self) -> None:
        self.events: list[dict[str, str]] = []
        self.incidents: list[dict[str, str]] = []

    def add(
        self,
        moment: datetime,
        message: str,
        *,
        identifier: str,
        unit: str = "",
        priority: str = "6",
    ) -> None:
        """Ajoute un événement, puis le tri final remettra tout en ordre."""
        self.events.append(
            {
                "__REALTIME_TIMESTAMP": _microseconds(moment),
                "_HOSTNAME": HOSTNAME,
                "SYSLOG_IDENTIFIER": identifier,
                "_SYSTEMD_UNIT": unit,
                "PRIORITY": priority,
                "MESSAGE": message,
            }
        )

    def incident(self, rule: str, moment: datetime, description: str) -> None:
        """Enregistre un incident injecté (attendu à la détection)."""
        self.incidents.append(
            {
                "rule": rule,
                "time_utc": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "description": description,
            }
        )

    def sorted_events(self) -> list[dict[str, str]]:
        """Retourne les événements triés par horodatage."""
        return sorted(self.events, key=lambda event: int(event["__REALTIME_TIMESTAMP"]))


# --------------------------------------------------------------------------
# Activité normale
# --------------------------------------------------------------------------


def add_normal_activity(builder: JournalBuilder, days: int, rng: random.Random) -> None:
    """Ajoute ~3 jours d'activité normale : rien à signaler.

    C'est la partie la plus importante du jeu de données : un détecteur qui
    alerte ici est un faux positif.
    """
    for day in range(days):
        day_start = START + timedelta(days=day)
        builder.add(
            day_start,
            "Startup finished in 3.412s (kernel) + 2.104s (userspace).",
            identifier="systemd",
        )
        builder.add(
            day_start + timedelta(seconds=12),
            "Started chronyd.service - NTP client/server.",
            identifier="systemd",
            unit="chronyd.service",
        )
        builder.add(
            day_start + timedelta(hours=6, minutes=25, seconds=1),
            "pam_unix(crond:session): session opened for user root by (uid=0)",
            identifier="crond",
        )

        # Journée de travail : connexions par clé et commandes sudo.
        for hour in range(9, 17):
            minute = rng.randint(0, 50)
            builder.add(
                day_start + timedelta(hours=hour, minutes=minute, seconds=rng.randint(0, 59)),
                (
                    f"Accepted publickey for labuser from {IP_ADMIN} port "
                    f"{rng.randint(40000, 60000)} ssh2: ED25519 SHA256:labkey"
                ),
                identifier="sshd",
            )
            builder.add(
                day_start + timedelta(hours=hour, minutes=minute + 5, seconds=rng.randint(0, 59)),
                (
                    f"labuser : TTY=pts/0 ; PWD=/home/labuser ; USER=root ; "
                    f"COMMAND=/usr/bin/dnf makecache"
                ),
                identifier="sudo",
                priority="6",
            )
            builder.add(
                day_start + timedelta(hours=hour, minutes=minute + 1, seconds=rng.randint(0, 59)),
                f"New session {hour} of user labuser.",
                identifier="systemd-logind",
            )

        # Un seul échec isolé par jour : une faute de frappe, pas une attaque.
        builder.add(
            day_start + timedelta(hours=11, minutes=42, seconds=8),
            f"Failed password for labuser from {IP_ADMIN} port 51022 ssh2",
            identifier="sshd",
            priority="4",
        )


# --------------------------------------------------------------------------
# Incidents injectés
# --------------------------------------------------------------------------


def add_brute_force(builder: JournalBuilder, day_start: datetime) -> None:
    """Scénario 1 : 12 échecs de mot de passe en 6 minutes depuis la même IP.

    Règle attendue : ``ssh_brute_force`` (1 alerte).
    Le compte « admin » existe : ce sont des lignes ``Failed password for``
    (et non ``invalid user``), donc la règle d'énumération ne s'applique pas.
    """
    start = day_start + timedelta(hours=3, minutes=12)
    for index in range(12):
        builder.add(
            start + timedelta(seconds=30 * index),
            f"Failed password for admin from {IP_BRUTEFORCE} port {50000 + index} ssh2",
            identifier="sshd",
            priority="4",
        )
    builder.incident(
        "ssh_brute_force",
        start,
        f"12 échecs de mot de passe pour « admin » depuis {IP_BRUTEFORCE} en 6 minutes",
    )


def add_enumeration(builder: JournalBuilder, day_start: datetime) -> None:
    """Scénario 2 : 7 noms de comptes différents essayés en ~3 minutes.

    Règle attendue : ``ssh_user_enumeration`` (1 alerte).
    Chaque essai produit deux lignes, comme le fait sshd : ``Invalid user``
    puis ``Failed password for invalid user``.
    """
    start = day_start + timedelta(hours=14, minutes=5)
    users = ["oracle", "test", "ftp", "www", "git", "backup", "postgres"]
    for index, user in enumerate(users):
        moment = start + timedelta(seconds=25 * index)
        builder.add(
            moment,
            f"Invalid user {user} from {IP_ENUM} port {41000 + index}",
            identifier="sshd",
            priority="4",
        )
        builder.add(
            moment + timedelta(seconds=1),
            f"Failed password for invalid user {user} from {IP_ENUM} port {41000 + index} ssh2",
            identifier="sshd",
            priority="4",
        )
    builder.incident(
        "ssh_user_enumeration",
        start,
        f"7 comptes différents essayés depuis {IP_ENUM} en 3 minutes",
    )


def add_success_after_failures(builder: JournalBuilder, day_start: datetime) -> None:
    """Scénario 3 : 4 échecs puis une connexion réussie (compte compromis).

    Règle attendue : ``ssh_success_after_failures`` (1 alerte, sévérité élevée).

    Le scénario est placé à 10 h 40 (horaires de travail) **exprès** : les
    règles doivent être testées séparément, sinon un même événement ferait
    deux alertes et le test « exactement les incidents injectés » deviendrait
    ambigu. Sur de vrais journaux, les chevauchements existent (voir
    docs/rules.md).
    """
    start = day_start + timedelta(hours=10, minutes=40)
    for index in range(4):
        builder.add(
            start + timedelta(seconds=20 * index),
            f"Failed password for labuser from {IP_COMPROMISE} port {52000 + index} ssh2",
            identifier="sshd",
            priority="4",
        )
    accepted = start + timedelta(minutes=2)
    builder.add(
        accepted,
        f"Accepted password for labuser from {IP_COMPROMISE} port 52999 ssh2",
        identifier="sshd",
    )
    builder.incident(
        "ssh_success_after_failures",
        accepted,
        f"4 échecs puis connexion réussie pour « labuser » depuis {IP_COMPROMISE}",
    )


def add_sudo_failures(builder: JournalBuilder, day_start: datetime) -> None:
    """Scénario 4 : 3 mots de passe sudo incorrects.

    Règle attendue : ``sudo_abuse`` (1 alerte).
    """
    start = day_start + timedelta(hours=9, minutes=30)
    for index in range(3):
        builder.add(
            start + timedelta(minutes=index),
            (
                "stagiaire : incorrect password attempt ; TTY=pts/1 ; "
                "PWD=/home/stagiaire ; USER=root ; COMMAND=/usr/bin/dnf install nmap"
            ),
            identifier="sudo",
            priority="4",
        )
    builder.incident(
        "sudo_abuse",
        start,
        "3 mots de passe sudo incorrects pour « stagiaire »",
    )


def add_account_creation(builder: JournalBuilder, day_start: datetime) -> None:
    """Scénario 5 : création d'un compte puis ajout au groupe wheel.

    Règles attendues : ``account_creation`` (2 alertes, une par ligne).
    """
    created = day_start + timedelta(hours=11, minutes=5)
    builder.add(
        created,
        (
            "new user: name=testuser, UID=1002, GID=1002, home=/home/testuser, "
            "shell=/bin/bash, from=/dev/pts/1, templates="
        ),
        identifier="useradd",
        priority="6",
    )
    promoted = day_start + timedelta(hours=11, minutes=11)
    builder.add(
        promoted,
        "add 'testuser' to group 'wheel'",
        identifier="usermod",
        priority="6",
    )
    builder.incident(
        "account_creation",
        created,
        "création du compte « testuser »",
    )
    builder.incident(
        "account_creation",
        promoted,
        "ajout de « testuser » au groupe « wheel » (escalade de privilèges)",
    )


def add_restart_loop(builder: JournalBuilder, day_start: datetime) -> None:
    """Scénario 6 : le service testapp redémarre 4 fois en 4 minutes.

    Règle attendue : ``service_restart_loop`` (1 alerte).
    """
    start = day_start + timedelta(hours=15, minutes=0)
    for index in range(4):
        moment = start + timedelta(minutes=index)
        builder.add(
            moment,
            "testapp.service: Main process exited, code=exited, status=1/FAILURE",
            identifier="systemd",
            unit="testapp.service",
            priority="3",
        )
        builder.add(
            moment + timedelta(seconds=5),
            "Started testapp.service - Application de test.",
            identifier="systemd",
            unit="testapp.service",
        )
    builder.incident(
        "service_restart_loop",
        start,
        "testapp.service a redémarré 4 fois en 4 minutes",
    )


def add_selinux_denials(builder: JournalBuilder, day_start: datetime) -> None:
    """Scénario 7 : 3 refus SELinux pour le processus httpd.

    Règle attendue : ``selinux_denied`` (1 alerte, regroupée par processus).
    """
    start = day_start + timedelta(hours=16, minutes=10)
    for index in range(3):
        builder.add(
            start + timedelta(seconds=40 * index),
            (
                'audit: type=1400 audit(1793491200.123:456): avc:  denied  { read } '
                f'for  pid={4000 + index} comm="httpd" name="secret{index}.txt" '
                'dev="dm-0" ino=12345 scontext=system_u:system_r:httpd_t:s0 '
                "tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0"
            ),
            identifier="audit",
            unit="auditd.service",
            priority="4",
        )
    builder.incident(
        "selinux_denied",
        start,
        "3 refus SELinux pour le processus « httpd »",
    )


def add_unusual_hours(builder: JournalBuilder, day_start: datetime) -> None:
    """Scénario 8 : connexion par clé à 3 h 20 du matin.

    Règle attendue : ``login_unusual_hours`` (1 alerte, sévérité faible).
    """
    moment = day_start + timedelta(hours=3, minutes=20)
    builder.add(
        moment,
        f"Accepted publickey for labuser from {IP_ADMIN} port 40512 ssh2: ED25519 SHA256:labkey",
        identifier="sshd",
    )
    builder.incident(
        "login_unusual_hours",
        moment,
        "connexion par clé de « labuser » à 03:20 (hors 8h–19h)",
    )


# --------------------------------------------------------------------------
# Programme principal
# --------------------------------------------------------------------------


def build_dataset(days: int = 3, seed: int = 42) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Construit la liste des événements et la liste des incidents attendus."""
    rng = random.Random(seed)
    builder = JournalBuilder()
    add_normal_activity(builder, days, rng)

    # Les incidents sont répartis sur les jours disponibles.
    day_starts = [START + timedelta(days=day) for day in range(days)]
    first, last = day_starts[0], day_starts[-1]

    add_brute_force(builder, first)
    add_enumeration(builder, first)
    add_success_after_failures(builder, first if days == 1 else day_starts[1])
    add_sudo_failures(builder, last)
    add_account_creation(builder, last)
    add_restart_loop(builder, last)
    add_selinux_denials(builder, last)
    add_unusual_hours(builder, last)

    return builder.sorted_events(), builder.incidents


def expected_alerts(incidents: list[dict[str, str]]) -> dict[str, int]:
    """Compte les alertes attendues par règle à partir des incidents injectés."""
    counts: dict[str, int] = {}
    for incident in incidents:
        counts[incident["rule"]] = counts.get(incident["rule"], 0) + 1
    return dict(sorted(counts.items()))


def write_jsonl(events: list[dict[str, str]], path: Path) -> None:
    """Écrit un objet JSON par ligne (format journalctl)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")


def main() -> int:
    """Point d'entrée du script."""
    parser = argparse.ArgumentParser(
        description="Génère un jeu de journaux synthétique au format journalctl -o json.",
    )
    parser.add_argument(
        "--out-dir",
        default=str(Path(__file__).parent / "sample"),
        help="Dossier de sortie (défaut : data/sample).",
    )
    parser.add_argument("--days", type=int, default=3, help="Nombre de jours (défaut : 3).")
    parser.add_argument("--seed", type=int, default=42, help="Graine aléatoire (défaut : 42).")
    args = parser.parse_args()

    if args.days < 1:
        parser.error("--days doit être au moins 1")

    events, incidents = build_dataset(days=args.days, seed=args.seed)

    out_dir = Path(args.out_dir)
    log_path = out_dir / "synthetic-3days.jsonl"
    write_jsonl(events, log_path)

    truth_path = out_dir / "expected_incidents.json"
    truth = {
        "file": log_path.name,
        "days": args.days,
        "seed": args.seed,
        "events": len(events),
        "parameters": DEFAULT_PARAMETERS,
        "expected_alerts": expected_alerts(incidents),
        "incidents": incidents,
    }
    truth_path.write_text(json.dumps(truth, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"{len(events)} événements écrits dans {log_path}")
    print(f"{len(incidents)} incidents injectés, vérité terrain : {truth_path}")
    for rule, count in truth["expected_alerts"].items():
        print(f"  {rule:<28} {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
