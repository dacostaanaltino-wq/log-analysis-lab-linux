# Procédure de test sur MA VM Fedora

Objectif : produire de **vrais** journaux, avec des incidents que je provoque
moi-même, puis vérifier que l'outil les retrouve. Tout se passe sur **ma** VM
et depuis **mon** poste, sur un réseau de lab.

> **Éthique.** Ces manipulations ne se font que vers ma VM. Un scan ou une
> série de mots de passe ratés vers une machine qui n'est pas la mienne est une
> infraction.

> **Prérequis.** VM Fedora du projet `linux-hardening-lab-fedora`, SSH actif et
> accès par clé testé. Si `fail2ban` y est déjà installé, il va bannir mon IP
> après quelques échecs : dans ce cas, `sudo systemctl stop fail2ban` le temps
> du test, puis relancer.

## Étape 1 — Relever l'heure de début

```bash
date -u '+%Y-%m-%d %H:%M:%S UTC'
```

Noter cette valeur : elle sert à comparer ce qui est attendu et ce qui est
détecté.

## Étape 2 — Provoquer les incidents (sur la VM, sauf mention)

### 2.1 — Échecs de mot de passe SSH (depuis mon poste)

```bash
for i in $(seq 1 6); do
  ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      -o NumberOfPasswordPrompts=1 labuser@ADRESSE-DE-MA-VM 2>&1 | tail -1
done
```

À chaque essai, saisir un mot de passe faux. Attendu : 6 lignes
`Failed password for labuser from <mon IP>` **de mon IP**.

> Si l'authentification par mot de passe est déjà désactivée (projet 2), ces
> essais produisent `Connection closed by authenticating user` et non
> `Failed password`. Dans ce cas, réactiver temporairement
> `PasswordAuthentication yes`, ou tester directement sur le jeu synthétique.

### 2.2 — Mauvais mot de passe `sudo` (sur la VM, dans la session de `labuser`)

```bash
sudo -k            # oublie le mot de passe mémorisé
sudo -k ls /root   # répondre 3 fois un mot de passe faux
```

Attendu : 3 lignes `labuser : 3 incorrect password attempts` (sudo les regroupe
parfois en une seule ligne mentionnant `3 incorrect password attempts`).

### 2.3 — Création de compte puis suppression (sur la VM)

```bash
sudo useradd -m testuser
sudo passwd -l testuser
sudo userdel -r testuser
```

Attendu : `new user: name=testuser`, puis les lignes de `userdel`.

### 2.4 — Plantage d'un service de test (sur la VM)

```bash
sudo tee /etc/systemd/system/testapp.service >/dev/null <<'EOF'
[Unit]
Description=Application de test (lab log-analysis)

[Service]
Type=simple
ExecStart=/bin/false
Restart=always
RestartSec=2s

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl start testapp.service
sleep 20
sudo systemctl stop testapp.service
sudo systemctl disable testapp.service
```

Attendu : plusieurs `Started testapp.service` et `Main process exited` en 20 s.
**Nettoyage obligatoire** ensuite :

```bash
sudo rm /etc/systemd/system/testapp.service
sudo systemctl daemon-reload
```

## Étape 3 — Collecter, assainir, analyser

```bash
# 1. collecte (sur la VM)
./scripts/collect.sh --since "30 minutes ago" --output raw-logs/test.jsonl

# 2. anonymisation AVANT tout commit
python3 tools/sanitize.py --input raw-logs/test.jsonl --output data/real/clean.jsonl
python3 tools/sanitize.py --check data/real/clean.jsonl

# 3. analyse
python3 -m loganalyzer analyze --input data/real/clean.jsonl \
    --window 10 --threshold 5 --out reports/real/
```

## Étape 4 — Comparer attendu et détecté

À remplir moi-même après le test (c'est la preuve du README) :

| Incident provoqué | Règle attendue | Détecté ? | Remarque |
|---|---|---|---|
| 6 mots de passe SSH faux | `ssh_brute_force` | ☐ oui ☐ non | |
| 3 mots de passe sudo faux | `sudo_abuse` | ☐ oui ☐ non | sudo peut regrouper les essais |
| `useradd testuser` | `account_creation` | ☐ oui ☐ non | |
| `testapp` en boucle | `service_restart_loop` | ☐ oui ☐ non | |
| Connexion hors horaires | `login_unusual_hours` | ☐ oui ☐ non | dépend de l'heure réelle |

## Ce qui peut ne pas fonctionner (et pourquoi)

| Problème | Explication |
|---|---|
| Aucun `Failed password` | l'authentification par mot de passe est désactivée (projet 2) : c'est une **bonne** nouvelle |
| Aucune alerte sudo | sudo regroupe les échecs en une seule ligne avec un compteur ; la règle se déclenche à partir de 3 lignes ou d'une ligne `NOT in sudoers` |
| Aucun AVC SELinux | la VM est en `Enforcing` mais rien ne viole la politique : normal |
| Rien du tout | les journaux peuvent être en mémoire (`Storage=volatile`) : `journalctl --disk-usage` le dit |

## Nettoyage final

```bash
rm -f raw-logs/test.jsonl data/real/clean.jsonl mapping.json
sudo systemctl stop fail2ban 2>/dev/null; sudo systemctl start fail2ban 2>/dev/null
```

Les fichiers de `raw-logs/` et `data/real/` ne sont jamais commités
(`.gitignore`). En cas de doute : `git status` avant chaque commit.
