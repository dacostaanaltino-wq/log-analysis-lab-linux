"""Tests des règles de détection : un cas positif ET un cas négatif par règle.

Les cas négatifs sont aussi importants que les positifs : un détecteur qui
alerte sur de l'activité normale est inutilisable (fatigue d'alerte).
"""

from __future__ import annotations

from collections.abc import Callable

from loganalyzer.detectors import (
    account_creation,
    brute_force,
    selinux_denials,
    service_restart_loop,
    success_after_failures,
    sudo_failures,
    unusual_hours,
    user_enumeration,
)
from loganalyzer.models import Config, Event


def _config(**overrides: object) -> Config:
    """Config par défaut des tests, avec surcharges ponctuelles."""
    return Config(**overrides)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Règle 1 – force brute SSH
# ---------------------------------------------------------------------------


def test_brute_force_positive(make_event: Callable[..., Event]) -> None:
    events = [
        make_event(
            minutes=index,
            message=f"Failed password for admin from 203.0.113.66 port {50000 + index} ssh2",
        )
        for index in range(7)
    ]
    alerts = brute_force.detect(events, _config())
    assert len(alerts) == 1
    assert alerts[0].rule == "ssh_brute_force"
    assert alerts[0].count == 7
    assert alerts[0].mitre == "T1110"


def test_brute_force_negative_echecs_disperses(make_event: Callable[..., Event]) -> None:
    # 4 échecs seulement : sous le seuil de 5.
    events = [
        make_event(minutes=index * 3, message=f"Failed password for admin from 203.0.113.66 port {index}")
        for index in range(4)
    ]
    assert brute_force.detect(events, _config()) == []


def test_brute_force_negative_ip_differente_par_echec(
    make_event: Callable[..., Event],
) -> None:
    # 5 échecs, mais depuis 5 IP différentes : ce n'est pas une force brute
    # dirigée contre un compte, c'est du bruit.
    events = [
        make_event(minutes=index, message=f"Failed password for admin from 203.0.113.{index} port 22 ssh2")
        for index in range(5)
    ]
    assert brute_force.detect(events, _config()) == []


def test_brute_force_ignore_les_utilisateurs_inexistants(
    make_event: Callable[..., Event],
) -> None:
    # « Failed password for invalid user » appartient à la règle d'énumération.
    events = [
        make_event(minutes=index, message=f"Failed password for invalid user test{index} from 198.51.100.23 port 22 ssh2")
        for index in range(10)
    ]
    assert brute_force.detect(events, _config()) == []


def test_brute_force_severite_haute_au_double_du_seuil(
    make_event: Callable[..., Event],
) -> None:
    events = [
        make_event(minutes=index * 0.2, message=f"Failed password for admin from 203.0.113.66 port {index}")
        for index in range(12)
    ]
    alerts = brute_force.detect(events, _config())
    assert alerts[0].severity == "high"


# ---------------------------------------------------------------------------
# Règle 2 – énumération de comptes
# ---------------------------------------------------------------------------


def test_user_enumeration_positive(make_event: Callable[..., Event]) -> None:
    users = ["oracle", "test", "ftp", "www", "git"]
    events = [
        make_event(minutes=index, message=f"Invalid user {user} from 198.51.100.23 port {41000 + index}")
        for index, user in enumerate(users)
    ]
    alerts = user_enumeration.detect(events, _config())
    assert len(alerts) == 1
    assert alerts[0].count == 5
    assert alerts[0].rule == "ssh_user_enumeration"


def test_user_enumeration_negative_meme_utilisateur(
    make_event: Callable[..., Event],
) -> None:
    events = [
        make_event(minutes=index, message="Invalid user test from 198.51.100.23 port 41000")
        for index in range(8)
    ]
    assert user_enumeration.detect(events, _config()) == []


def test_user_enumeration_negative_ip_differente_each(
    make_event: Callable[..., Event],
) -> None:
    events = [
        make_event(minutes=index, message=f"Invalid user user{index} from 198.51.100.{index} port 41000")
        for index in range(6)
    ]
    assert user_enumeration.detect(events, _config()) == []


# ---------------------------------------------------------------------------
# Règle 3 – succès après échecs
# ---------------------------------------------------------------------------


def test_success_after_failures_positive(make_event: Callable[..., Event]) -> None:
    events = [
        make_event(minutes=index, message=f"Failed password for labuser from 203.0.113.77 port {52000 + index} ssh2")
        for index in range(4)
    ]
    events.append(
        make_event(minutes=5, message="Accepted password for labuser from 203.0.113.77 port 52999 ssh2")
    )
    alerts = success_after_failures.detect(events, _config())
    assert len(alerts) == 1
    assert alerts[0].severity == "high"
    assert alerts[0].mitre == "T1078"


def test_success_after_failures_negative_trop_peu_d_echecs(
    make_event: Callable[..., Event],
) -> None:
    events = [
        make_event(minutes=index, message=f"Failed password for labuser from 203.0.113.77 port {52000 + index} ssh2")
        for index in range(3)
    ]
    events.append(
        make_event(minutes=5, message="Accepted password for labuser from 203.0.113.77 port 52999 ssh2")
    )
    assert success_after_failures.detect(events, _config()) == []


def test_success_after_failures_negative_connexion_normale(
    make_event: Callable[..., Event],
) -> None:
    events = [
        make_event(minutes=0, message="Accepted publickey for labuser from 192.0.2.10 port 40000 ssh2"),
    ]
    assert success_after_failures.detect(events, _config()) == []


def test_success_after_failures_negative_echecs_trop_anciens(
    make_event: Callable[..., Event],
) -> None:
    # 4 échecs puis un succès 40 minutes plus tard : hors fenêtre de 10 minutes.
    events = [
        make_event(minutes=index, message=f"Failed password for labuser from 203.0.113.77 port {index} ssh2")
        for index in range(4)
    ]
    events.append(
        make_event(minutes=44, message="Accepted password for labuser from 203.0.113.77 port 52999 ssh2")
    )
    assert success_after_failures.detect(events, _config()) == []


# ---------------------------------------------------------------------------
# Règle 4 – sudo
# ---------------------------------------------------------------------------


def test_sudo_failures_positive(make_event: Callable[..., Event]) -> None:
    events = [
        make_event(
            minutes=index,
            identifier="sudo",
            message="stagiaire : incorrect password attempt ; TTY=pts/1 ; USER=root",
        )
        for index in range(3)
    ]
    alerts = sudo_failures.detect(events, _config())
    assert len(alerts) == 1
    assert alerts[0].severity == "medium"
    assert alerts[0].mitre == "T1548.003"


def test_sudo_failures_negative_deux_essais(make_event: Callable[..., Event]) -> None:
    events = [
        make_event(
            minutes=index,
            identifier="sudo",
            message="stagiaire : incorrect password attempt ; TTY=pts/1 ; USER=root",
        )
        for index in range(2)
    ]
    assert sudo_failures.detect(events, _config()) == []


def test_sudo_failures_detecte_l_absence_de_droit(make_event: Callable[..., Event]) -> None:
    events = [
        make_event(
            minutes=0,
            identifier="sudo",
            message="labuser : user NOT in sudoers ; TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/dnf",
        )
    ]
    alerts = sudo_failures.detect(events, _config())
    assert len(alerts) == 1
    assert alerts[0].severity == "high"


def test_sudo_failures_negative_sudo_normal(make_event: Callable[..., Event]) -> None:
    events = [
        make_event(
            minutes=index,
            identifier="sudo",
            message="labuser : TTY=pts/0 ; PWD=/home/labuser ; USER=root ; COMMAND=/usr/bin/dnf makecache",
        )
        for index in range(6)
    ]
    assert sudo_failures.detect(events, _config()) == []


# ---------------------------------------------------------------------------
# Règle 5 – création de compte
# ---------------------------------------------------------------------------


def test_account_creation_positive(make_event: Callable[..., Event]) -> None:
    events = [
        make_event(
            minutes=0,
            identifier="useradd",
            message="new user: name=testuser, UID=1002, GID=1002, home=/home/testuser",
        ),
        make_event(minutes=6, identifier="usermod", message="add 'testuser' to group 'wheel'"),
    ]
    alerts = account_creation.detect(events, _config())
    assert len(alerts) == 2
    assert alerts[0].severity == "medium"
    assert alerts[1].severity == "high"  # ajout au groupe wheel
    assert alerts[0].mitre == "T1136"


def test_account_creation_negative_activite_normale(
    make_event: Callable[..., Event],
) -> None:
    events = [
        make_event(minutes=0, identifier="sshd", message="Accepted publickey for labuser from 192.0.2.10 port 40000"),
        make_event(minutes=1, identifier="sudo", message="labuser : TTY=pts/0 ; USER=root"),
        make_event(minutes=2, identifier="systemd", message="Started chronyd.service - NTP client/server."),
    ]
    assert account_creation.detect(events, _config()) == []


# ---------------------------------------------------------------------------
# Règle 6 – boucle de redémarrage
# ---------------------------------------------------------------------------


def test_service_restart_loop_positive(make_event: Callable[..., Event]) -> None:
    events = [
        make_event(
            minutes=index,
            identifier="systemd",
            unit="testapp.service",
            message="Started testapp.service - Application de test.",
        )
        for index in range(4)
    ]
    alerts = service_restart_loop.detect(events, _config())
    assert len(alerts) == 1
    assert alerts[0].count == 4
    assert alerts[0].rule == "service_restart_loop"


def test_service_restart_loop_negative_deux_demarrages(
    make_event: Callable[..., Event],
) -> None:
    events = [
        make_event(minutes=index * 5, identifier="systemd", message="Started testapp.service - Application de test.")
        for index in range(2)
    ]
    assert service_restart_loop.detect(events, _config()) == []


# ---------------------------------------------------------------------------
# Règle 7 – refus SELinux
# ---------------------------------------------------------------------------


def test_selinux_denied_positive(make_event: Callable[..., Event]) -> None:
    events = [
        make_event(
            minutes=index,
            identifier="audit",
            message=(
                'audit: type=1400 audit(1793491200.123:456): avc:  denied  { read } for  '
                f'pid={4000 + index} comm="httpd" name="secret.txt" tclass=file permissive=0'
            ),
        )
        for index in range(3)
    ]
    alerts = selinux_denials.detect(events, _config())
    assert len(alerts) == 1
    assert alerts[0].count == 3
    assert alerts[0].severity == "medium"


def test_selinux_denied_negative_sans_refus(make_event: Callable[..., Event]) -> None:
    events = [
        make_event(minutes=0, identifier="audit", message='type=1400 audit(1.1:2): avc:  granted  { read } for comm="httpd"')
    ]
    assert selinux_denials.detect(events, _config()) == []


# ---------------------------------------------------------------------------
# Règle 8 – horaires inhabituels
# ---------------------------------------------------------------------------


def test_unusual_hours_positive(make_event: Callable[..., Event]) -> None:
    # BASE correspond à 10 h UTC ; on décale de -7 h pour arriver à 3 h du matin.
    event = make_event(minutes=-420, message="Accepted publickey for labuser from 192.0.2.10 port 40000 ssh2")
    alerts = unusual_hours.detect([event], _config())
    assert len(alerts) == 1
    assert alerts[0].severity == "low"


def test_unusual_hours_negative_heures_de_travail(
    make_event: Callable[..., Event],
) -> None:
    events = [
        make_event(minutes=index * 30, message="Accepted publickey for labuser from 192.0.2.10 port 40000 ssh2")
        for index in range(6)
    ]
    assert unusual_hours.detect(events, _config()) == []


def test_unusual_hours_negative_plage_personnalisee(
    make_event: Callable[..., Event],
) -> None:
    # 10 h UTC est dans la plage 8h-19h mais hors de la plage 0h-6h.
    event = make_event(minutes=0, message="Accepted password for labuser from 192.0.2.10 port 40000 ssh2")
    assert unusual_hours.detect([event], _config(business_hours=(8, 19))) == []
    assert len(unusual_hours.detect([event], _config(business_hours=(0, 6)))) == 1


def test_unusual_hours_fuseau_inconnu_ne_plante_pas(
    make_event: Callable[..., Event],
) -> None:
    event = make_event(minutes=0, message="Accepted password for labuser from 192.0.2.10 port 40000 ssh2")
    alerts = unusual_hours.detect([event], _config(timezone_name="Mars/Olympus_Mons"))
    assert alerts == []
