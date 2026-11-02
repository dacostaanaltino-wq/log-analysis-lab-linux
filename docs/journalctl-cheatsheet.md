# Aide-mémoire `journalctl`

Toutes les options de cette page ont été vérifiées dans `man journalctl`
(systemd 259 sur Fedora 44). Vérifie la tienne avec `man journalctl` avant de
recopier une commande : les options évoluent d'une version à l'autre.

## Lire les journaux

```bash
journalctl                          # depuis le début du journal courant, avec pager
journalctl -n 50                    # les 50 dernières lignes
journalctl -f                       # suivi en direct (comme tail -f)
journalctl --no-pager               # sans pager (utile dans un script)
journalctl -u sshd                  # une unité systemd
journalctl -u testapp -n 100        # les 100 dernières lignes de testapp
journalctl -b                       # depuis le démarrage courant
journalctl -b -1                    # le démarrage précédent
journalctl --list-boots             # liste des démarrages
journalctl -k                       # messages du noyau (comme dmesg)
journalctl -p err                   # priorité err et plus grave
journalctl --utc                    # horodatages en UTC (recommandé pour l'export)
```

## Filtrer par temps

```bash
journalctl --since "2026-10-27"                 # depuis minuit
journalctl --since "2026-10-27 08:00" --until "2026-10-27 12:00"
journalctl --since "3 days ago"
journalctl --since yesterday
journalctl --since "-1h"                        # une heure en arrière
```

Formats acceptés : `AAAA-MM-JJ HH:MM:SS`, `yesterday`, `today`, `now`, et les
temps relatifs avec préfixe `-` (avant) ou `+` (après).

## Filtrer par contenu

```bash
journalctl --grep "Failed password"             # expression régulière
journalctl --grep "avc:  denied" -u auditd
journalctl --case-sensitive --grep "Denied"
journalctl -t sshd                              # par identifiant syslog
journalctl --identifier=sudo
journalctl --user-unit=mon-service              # unité utilisateur
journalctl --facility=auth                      # par facilité syslog
journalctl _UID=1000                            # par champ (voir --fields)
journalctl --fields                             # liste des champs disponibles
```

Attention : `--grep` ne cherche que dans le **message**, pas dans tous les champs.

## Exporter (ce que consomme `loganalyzer`)

```bash
journalctl --since "3 days ago" -o json > journal.jsonl      # une ligne JSON par événement
journalctl -o json-pretty -n 1                                # un objet lisible
journalctl -o json --output-fields=_HOSTNAME,MESSAGE,PRIORITY  # champs choisis
journalctl -o export > journal.export                        # format binaire de journald
journalctl -o cat                                            # message seul (lisible)
```

Les champs utilisés par l'outil :

| Champ | Contenu |
|---|---|
| `__REALTIME_TIMESTAMP` | horodatage en **microsecondes** depuis l'époque UNIX |
| `MESSAGE` | le texte de l'événement |
| `SYSLOG_IDENTIFIER` | programme émetteur (`sshd`, `sudo`, `systemd`…) |
| `_SYSTEMD_UNIT` | unité systemd (`testapp.service`) |
| `PRIORITY` | priorité syslog de 0 (emerg) à 7 (debug) |
| `_HOSTNAME` | nom de la machine (à anonymiser avant publication) |

## Disque et maintenance

```bash
journalctl --disk-usage                       # taille du journal
sudo journalctl --vacuum-time=7d              # ne garder que 7 jours
sudo journalctl --vacuum-size=200M            # limiter la taille
sudo journalctl --rotate                      # forcer une rotation
```

Configuration durable de la taille : `/etc/systemd/journald.conf` (option
`SystemMaxUse=`), puis `sudo systemctl restart systemd-journald`.

## Vérifier un fichier exporté

```bash
journalctl --file=journal.jsonl --no-pager    # relire un export
journalctl --verify                           # intégrité du journal
```

## Permissions

Lire le journal système demande d'être `root` ou membre des groupes
`systemd-journal` / `adm` (selon la distribution). Pour un compte non privilégié :

```bash
sudo usermod -aG systemd-journal "$USER"      # puis se reconnecter
```

## Erreurs classiques

| Symptôme | Cause probable |
|---|---|
| `No journal files were found` | le journal est en mémoire (`Storage=volatile`) ou l'utilisateur n'a pas les droits |
| `Failed to add match` | faute de frappe dans un nom de champ (`_SYSTEMD_UNIT` et non `SYSTEMD_UNIT`) |
| Dates décalées | `--utc` absent : `journalctl` affiche l'heure locale |
| `--grep` ne trouve rien | la chaîne est dans un autre champ que `MESSAGE` |
