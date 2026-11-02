#!/usr/bin/env python3
"""Nettoie un journal RÉEL avant de le partager (anonymisation).

Un journal ``journalctl -o json`` contient des adresses IP, des noms
d'utilisateur, des noms de machine et parfois des chemins personnels. Ce script
remplace ces valeurs par des **pseudonymes cohérents** : la même IP réelle
devient toujours la même IP fictive, ce qui garde l'analyse lisible.

Règles :
  * adresses IP  -> plage de documentation RFC 5737 (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24) ; les IP déjà dans ces plages ne sont pas modifiées ;
  * noms d'utilisateur -> ``utilisateur-1``, ``utilisateur-2``, ...
  * noms de machine -> ``hote-lab-1``, ``hote-lab-2``, ...

Usage :
    python3 tools/sanitize.py --input raw-logs/journal.jsonl --output clean.jsonl
    python3 tools/sanitize.py --check clean.jsonl     # vérifie avant publication

Le fichier de correspondance (``--mapping-out``) est une donnée sensible :
ne le commite jamais.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from ipaddress import ip_address
from pathlib import Path

# --------------------------------------------------------------------------
# Expressions régulières
# --------------------------------------------------------------------------

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Plages autorisées dans un dépôt public (RFC 5737 + boucle locale).
DOCUMENTATION_NETS = ("192.0.2.", "198.51.100.", "203.0.113.", "127.")

# Motifs qui encadrent un nom d'utilisateur dans les journaux courants.
USER_PATTERNS = (
    re.compile(r"\bfor invalid user (?P<user>[A-Za-z0-9._-]+)"),
    re.compile(r"\bfor (?P<user>[A-Za-z0-9._-]+) from"),
    re.compile(r"\buser=(?P<user>[A-Za-z0-9._-]+)"),
    re.compile(r"\bnew user: name=(?P<user>[A-Za-z0-9._-]+)"),
    re.compile(r"\badd '(?P<user>[^']+)' to group"),
    re.compile(r"\bsession opened for user (?P<user>[A-Za-z0-9._-]+)"),
    re.compile(r"\bfor user (?P<user>[A-Za-z0-9._-]+)"),
    re.compile(r"^(?P<user>[A-Za-z0-9._-]+) : "),
)

# Mots qui ne sont pas des personnes : inutile de les pseudonymiser.
STOPWORDS = {"root", "invalid", "user", "sudo", "nobody"}

#: Adresses fictives allouées, dans l'ordre de rencontre.
IP_POOL = [f"192.0.2.{n}" for n in range(1, 255)] + [f"198.51.100.{n}" for n in range(1, 255)]


class Pseudonymizer:
    """Traduit les valeurs réelles en pseudonymes, de façon cohérente."""

    def __init__(self) -> None:
        self.ips: dict[str, str] = {}
        self.users: dict[str, str] = {}
        self.hosts: dict[str, str] = {}

    # -- IP ---------------------------------------------------------------
    def ip(self, value: str) -> str:
        """Retourne le pseudonyme d'une adresse IP."""
        if value.startswith(DOCUMENTATION_NETS):
            return value
        if value not in self.ips:
            index = len(self.ips)
            self.ips[value] = IP_POOL[index % len(IP_POOL)]
        return self.ips[value]

    # -- Utilisateur ------------------------------------------------------
    def user(self, value: str) -> str:
        """Retourne le pseudonyme d'un nom d'utilisateur."""
        if value in STOPWORDS or value.isdigit():
            return value
        if value not in self.users:
            self.users[value] = f"utilisateur-{len(self.users) + 1}"
        return self.users[value]

    # -- Machine ----------------------------------------------------------
    def host(self, value: str) -> str:
        """Retourne le pseudonyme d'un nom de machine."""
        if not value:
            return value
        if value not in self.hosts:
            self.hosts[value] = f"hote-lab-{len(self.hosts) + 1}"
        return self.hosts[value]

    # -- Texte ------------------------------------------------------------
    def text(self, value: str) -> str:
        """Anonymise une ligne de message : utilisateurs puis IP."""
        result = value
        for pattern in USER_PATTERNS:
            for match in list(pattern.finditer(result)):
                name = match.group("user")
                pseudo = self.user(name)
                if pseudo != name:
                    result = re.sub(rf"\b{re.escape(name)}\b", pseudo, result)
        for match in list(IPV4_RE.finditer(result)):
            result = result.replace(match.group(0), self.ip(match.group(0)))
        return result

    def mapping(self) -> dict[str, dict[str, str]]:
        """Correspondance réelle -> pseudonyme (donnée sensible)."""
        return {"ip": self.ips, "utilisateur": self.users, "machine": self.hosts}


def sanitize_record(record: dict, pseudo: Pseudonymizer) -> dict:
    """Retourne une copie assainie d'un enregistrement de journal."""
    clean = dict(record)
    if "MESSAGE" in clean:
        clean["MESSAGE"] = pseudo.text(str(clean["MESSAGE"]))
    if "_HOSTNAME" in clean:
        clean["_HOSTNAME"] = pseudo.host(str(clean["_HOSTNAME"]))
    # Certains champs d'auditd contiennent aussi des noms de comptes.
    for field in ("_COMM", "EXE", "_CMDLINE"):
        if field in clean:
            clean[field] = pseudo.text(str(clean[field]))
    return clean


def sanitize_file(source: Path, destination: Path, keep_mapping: Path | None = None) -> int:
    """Assainit un fichier JSON Lines. Retourne le nombre de lignes écrites."""
    pseudo = Pseudonymizer()
    written = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open(encoding="utf-8") as reader, destination.open(
        "w", encoding="utf-8"
    ) as writer:
        for number, line in enumerate(reader, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as exc:
                print(f"Ligne {number} ignorée (JSON invalide) : {exc}", file=sys.stderr)
                continue
            if not isinstance(record, dict):
                print(f"Ligne {number} ignorée (pas un objet JSON)", file=sys.stderr)
                continue
            writer.write(json.dumps(sanitize_record(record, pseudo), ensure_ascii=False) + "\n")
            written += 1

    if keep_mapping is not None:
        keep_mapping.write_text(
            json.dumps(pseudo.mapping(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(
            f"ATTENTION : {keep_mapping} contient les vraies valeurs. "
            "Ne le commite jamais et supprime-le après usage.",
            file=sys.stderr,
        )
    return written


def find_leftover_ips(path: Path) -> list[tuple[int, str]]:
    """Retourne les lignes qui contiennent encore une IP non documentaire."""
    leftovers: list[tuple[int, str]] = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            for match in IPV4_RE.finditer(line):
                candidate = match.group(0)
                try:
                    address = ip_address(candidate)
                except ValueError:
                    continue  # ex. « 1.2.3.4.5 » ou une version de logiciel
                if not address.is_private and not candidate.startswith(DOCUMENTATION_NETS):
                    leftovers.append((number, candidate))
                elif address.is_private and not candidate.startswith(DOCUMENTATION_NETS):
                    leftovers.append((number, candidate))
    return leftovers


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée du script."""
    parser = argparse.ArgumentParser(
        description="Anonymise un journal journalctl avant publication.",
        epilog="Le fichier de correspondance est sensible : ne le commite jamais.",
    )
    parser.add_argument("--input", metavar="FICHIER", help="Journal à assainir.")
    parser.add_argument("--output", metavar="FICHIER", help="Journal assaini à écrire.")
    parser.add_argument(
        "--mapping-out",
        metavar="FICHIER",
        help="Écrit la correspondance réelle -> pseudonyme (sensible, ne pas publier).",
    )
    parser.add_argument(
        "--check",
        metavar="FICHIER",
        help="Vérifie qu'aucune adresse IP réelle ne reste dans un fichier (code 1 si oui).",
    )
    args = parser.parse_args(argv)

    if args.check:
        leftovers = find_leftover_ips(Path(args.check))
        if leftovers:
            print(f"{len(leftovers)} adresse(s) IP à anonymiser dans {args.check} :", file=sys.stderr)
            for number, candidate in leftovers[:20]:
                print(f"  ligne {number} : {candidate}", file=sys.stderr)
            return 1
        print(f"Aucune adresse IP réelle détectée dans {args.check}.")
        return 0

    if not args.input or not args.output:
        parser.error("--input et --output sont obligatoires (ou utiliser --check)")

    source = Path(args.input)
    if not source.is_file():
        print(f"Erreur : fichier introuvable : {source}", file=sys.stderr)
        return 2

    written = sanitize_file(source, Path(args.output), Path(args.mapping_out) if args.mapping_out else None)
    print(f"{written} événements assainis dans {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
