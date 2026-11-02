# Vérité terrain du jeu de données synthétique

Fichier : `data/sample/synthetic-3days.jsonl` (une ligne JSON par événement,
format `journalctl -o json`).
Généré par : `python3 data/generate_sample_logs.py` (**déterministe**, graine 42).
Paramètres attendus de l'analyse : recopiés dans `data/sample/expected_incidents.json`.

| Élément | Valeur |
|---|---|
| Période | 27/10/2026 00:00 → 29/10/2026 16:11 (UTC) |
| Nombre d'événements | 132 |
| Machine | `lab-vm` (nom fictif) |
| Adresses IP | uniquement des plages de documentation RFC 5737 |
| Comptes | `labuser`, `stagiaire`, `testuser`, `admin` (tous fictifs) |

L'activité « normale » (connexions par clé entre 9 h et 16 h, commandes `sudo`
légitimes, démarrage des services, un seul échec de mot de passe isolé par jour)
sert de **piège à faux positifs** : un détecteur qui alerte dessus est cassé.

## Incidents injectés

| # | Règle attendue | Date/heure (UTC) | Description |
|---|---|---|---|
| 1 | `ssh_brute_force` | 27/10 03:12 | 12 échecs de mot de passe pour `admin` depuis `203.0.113.66` en 6 minutes |
| 2 | `ssh_user_enumeration` | 27/10 14:05 | 7 comptes différents essayés depuis `198.51.100.23` en 3 minutes |
| 3 | `ssh_success_after_failures` | 28/10 10:42 | 4 échecs puis connexion réussie pour `labuser` depuis `203.0.113.77` |
| 4 | `sudo_abuse` | 29/10 09:30 | 3 mots de passe `sudo` incorrects pour `stagiaire` |
| 5 | `account_creation` | 29/10 11:05 | création de `testuser` (`useradd`) |
| 6 | `account_creation` | 29/10 11:11 | `testuser` ajouté au groupe `wheel` (`usermod`) |
| 7 | `service_restart_loop` | 29/10 15:00 | `testapp.service` redémarré 4 fois en 4 minutes |
| 8 | `selinux_denied` | 29/10 16:10 | 3 refus SELinux pour `httpd` |
| 9 | `login_unusual_hours` | 29/10 03:20 | connexion par clé à 3 h 20 du matin |

Avec la configuration par défaut (`--window 10 --threshold 5`), l'analyse doit
produire **exactement 9 alertes** réparties ainsi :

```json
{
  "account_creation": 2,
  "login_unusual_hours": 1,
  "selinux_denied": 1,
  "service_restart_loop": 1,
  "ssh_brute_force": 1,
  "ssh_success_after_failures": 1,
  "ssh_user_enumeration": 1,
  "sudo_abuse": 1
}
```

C'est ce que vérifie `tests/test_synthetic_dataset.py`.

## Pourquoi les scénarios ne se chevauchent pas

Sur de **vrais** journaux, un même événement déclenche souvent deux règles : une
énumération de comptes (`Invalid user`) est aussi une série d'échecs, et une
connexion réussie à 3 h du matin déclenche à la fois `ssh_success_after_failures`
et `login_unusual_hours`.

Dans ce jeu de données, les incidents sont placés de façon à **isoler** chaque
règle (le scénario 3 est à 10 h 42, pas à 3 h du matin) : c'est une exigence de
testabilité, pas une simplification du monde réel. Les chevauchements réels sont
discutés dans [`docs/rules.md`](../docs/rules.md).

## Adresses IP utilisées

| Adresse | Rôle |
|---|---|
| `192.0.2.10` | poste d'administration (trafic normal) |
| `203.0.113.66` | force brute SSH |
| `198.51.100.23` | énumération de comptes |
| `203.0.113.77` | compte compromis (échecs puis succès) |

Aucune de ces adresses n'appartient à quelqu'un : ce sont les plages réservées à
la documentation par la RFC 5737.

## Régénérer

```bash
python3 data/generate_sample_logs.py                 # mêmes fichiers, contenu identique
python3 data/generate_sample_logs.py --days 5 --seed 7
```

Après régénération, `tests/test_synthetic_dataset.py` vérifie que le fichier
publié est bien celui que produit le générateur.
