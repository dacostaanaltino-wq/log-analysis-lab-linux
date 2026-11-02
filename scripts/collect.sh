#!/usr/bin/env bash
# scripts/collect.sh – collecte les journaux RÉELS de la VM de lab.
#
# Ce script ne fait que lire : `journalctl` n'a besoin d'aucun privilège pour
# lire les journaux des services (groupes systemd-journal / adm selon le cas).
# Les fichiers produits contiennent des données personnelles : ils vont dans
# raw-logs/, qui est dans .gitignore, et doivent passer par tools/sanitize.py
# AVANT tout partage.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

SINCE="3 days ago"
OUTPUT=""
DRY_RUN=0

usage() {
    cat <<'EOF'
collect.sh – exporte les journaux systemd au format JSON Lines.

Usage : ./scripts/collect.sh [OPTIONS]

Options :
  -s, --since DATE   Début de la collecte (défaut : "3 days ago").
                     Tout format accepté par journalctl --since :
                     "2026-10-27", "yesterday", "1 hour ago".
  -o, --output FILE  Fichier de sortie (défaut : raw-logs/journal-<date>.jsonl).
  -n, --dry-run      Affiche la commande sans l'exécuter.
  -h, --help         Affiche cette aide.

Après la collecte (obligatoire avant publication) :
  python3 tools/sanitize.py --input raw-logs/xxx.jsonl --output data/real/clean.jsonl
  python3 tools/sanitize.py --check data/real/clean.jsonl
EOF
}

while (($# > 0)); do
    case "$1" in
        -s | --since)
            [[ $# -ge 2 ]] || { echo "L'option $1 demande un argument." >&2; exit 2; }
            SINCE="$2"
            shift 2
            ;;
        -o | --output)
            [[ $# -ge 2 ]] || { echo "L'option $1 demande un argument." >&2; exit 2; }
            OUTPUT="$2"
            shift 2
            ;;
        -n | --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "Option inconnue : $1 (voir --help)" >&2
            exit 2
            ;;
    esac
done

command -v journalctl >/dev/null 2>&1 || {
    echo "journalctl est absent : ce script doit tourner sur la machine analysée." >&2
    exit 1
}

if [[ -z "$OUTPUT" ]]; then
    OUTPUT="$REPO_DIR/raw-logs/journal-$(date -u '+%Y%m%dT%H%M%SZ').jsonl"
fi

echo "Collecte : journalctl --since \"$SINCE\" -o json" >&2
echo "Sortie   : $OUTPUT" >&2

if ((DRY_RUN)); then
    echo "[DRY-RUN] journalctl --since \"$SINCE\" -o json > $OUTPUT" >&2
    exit 0
fi

mkdir -p "$(dirname "$OUTPUT")"
journalctl --since "$SINCE" -o json >"$OUTPUT"

lines=$(wc -l <"$OUTPUT")
echo "$lines événements écrits dans $OUTPUT" >&2
echo "RAPPEL : ce fichier contient des données réelles. Il est ignoré par git." >&2
echo "Étape suivante : python3 tools/sanitize.py --input \"$OUTPUT\" --output data/real/clean.jsonl" >&2
