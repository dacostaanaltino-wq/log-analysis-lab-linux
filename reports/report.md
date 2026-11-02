# Rapport d'analyse de journaux

- **Source** : `synthetic-3days.jsonl`
- **Événements analysés** : 132
- **Période couverte** : 2026-10-27 00:00:00 → 2026-10-29 16:11:20 (UTC)
- **Fenêtre de détection** : 10 minutes
- **Seuil d'échecs (brute force)** : 5
- **Horaires de travail** : 8h–19h (UTC)
- **Rapport généré le** : 2026-11-01 19:07:50 UTC

## Résumé

| Sévérité | Nombre d'alertes |
|---|---|
| ÉLEVÉE | 3 |
| MOYENNE | 5 |
| FAIBLE | 1 |
| **Total** | **9** |

## Alertes

| # | Horodatage (UTC) | Sévérité | Règle | MITRE | Détail | Preuve (ligne de journal) |
|---|---|---|---|---|---|---|
| 1 | 2026-10-27 03:12:00 | ÉLEVÉE | `ssh_brute_force` | T1110 | 12 échecs de mot de passe SSH depuis 203.0.113.66 en 10 minutes ou moins | `Failed password for admin from 203.0.113.66 port 50011 ssh2` |
| 2 | 2026-10-28 10:42:00 | ÉLEVÉE | `ssh_success_after_failures` | T1078 | Connexion réussie pour « labuser » depuis 203.0.113.77 après 4 échecs | `Accepted password for labuser from 203.0.113.77 port 52999 ssh2` |
| 3 | 2026-10-29 11:11:00 | ÉLEVÉE | `account_creation` | T1136 | Utilisateur « testuser » ajouté au groupe « wheel » | `add 'testuser' to group 'wheel'` |
| 4 | 2026-10-27 14:05:00 | MOYENNE | `ssh_user_enumeration` | T1087 | 7 noms de comptes différents essayés depuis 198.51.100.23 en 10 minutes ou moins | `Invalid user postgres from 198.51.100.23 port 41006` |
| 5 | 2026-10-29 09:30:00 | MOYENNE | `sudo_abuse` | T1548.003 | 3 mots de passe sudo incorrects pour l'utilisateur « stagiaire » | `stagiaire : incorrect password attempt ; TTY=pts/1 ; PWD=/home/stagiaire ; USER=root ; COMMAND=/usr/bin/dnf i…` |
| 6 | 2026-10-29 11:05:00 | MOYENNE | `account_creation` | T1136 | Nouveau compte créé : « testuser » | `new user: name=testuser, UID=1002, GID=1002, home=/home/testuser, shell=/bin/bash, from=/dev/pts/1, templates=` |
| 7 | 2026-10-29 15:00:05 | MOYENNE | `service_restart_loop` | — | Le service testapp.service a démarré 4 fois en 10 minutes ou moins | `Started testapp.service - Application de test.` |
| 8 | 2026-10-29 16:10:00 | MOYENNE | `selinux_denied` | — | 3 refus SELinux pour le processus « httpd » | `audit: type=1400 audit(1793491200.123:456): avc:  denied  { read } for  pid=4002 comm="httpd" name="secret2.t…` |
| 9 | 2026-10-29 03:20:00 | FAIBLE | `login_unusual_hours` | — | Connexion réussie de « labuser » à 03:20 (UTC), hors plage 8h–19h | `Accepted publickey for labuser from 192.0.2.10 port 40512 ssh2: ED25519 SHA256:labkey` |

## Recommandations

### `account_creation` — 2 alerte(s)

Création de compte ou modification de groupe privilégié.

**À faire** : Vérifier que la création est autorisée (ticket, fenêtre de maintenance). Si non : supprimer le compte, révoquer ses clés et chercher la persistance.

### `login_unusual_hours` — 1 alerte(s)

Connexion réussie en dehors des horaires de travail définis.

**À faire** : Vérifier avec l'utilisateur que la connexion est légitime (astreinte, déplacement) ; sinon, considérer le compte comme compromis.

### `selinux_denied` — 1 alerte(s)

Refus SELinux (avc: denied) regroupés par processus.

**À faire** : Lire le refus avec ausearch -m AVC -ts recent, puis corriger l'étiquette (restorecon/semanage) au lieu de passer SELinux en permissive.

### `service_restart_loop` — 1 alerte(s)

Service démarré plusieurs fois en peu de temps (boucle de redémarrage).

**À faire** : Consulter journalctl -u <service> -n 50, corriger la cause (configuration, droits, mémoire) et poser une limite de redémarrage si nécessaire.

### `ssh_brute_force` — 1 alerte(s)

Échecs de mot de passe SSH répétés depuis une même IP.

**À faire** : Bloquer l'IP au niveau du pare-feu, vérifier qu'aucun compte n'a été compromis, et imposer l'authentification par clé.

### `ssh_success_after_failures` — 1 alerte(s)

Connexion SSH réussie après plusieurs échecs depuis la même IP.

**À faire** : Traiter le compte comme compromis : changer le mot de passe, révoquer les clés, relire les commandes exécutées (auditd) et chercher la persistance.

### `ssh_user_enumeration` — 1 alerte(s)

Tentatives sur de nombreux noms de comptes différents depuis une même IP.

**À faire** : Bloquer l'IP, désactiver l'authentification par mot de passe et vérifier qu'aucun compte par défaut ne reste actif.

### `sudo_abuse` — 1 alerte(s)

Échecs sudo répétés ou tentative de sudo sans autorisation.

**À faire** : Vérifier qui utilise le compte, contrôler /etc/sudoers, et ajouter une règle fail2ban ou auditd si la tentative est répétée.

## Comment lire ce rapport

- Les heures sont en **UTC** (sauf mention contraire).
- Chaque alerte cite **la ligne de journal** qui la justifie : c'est la preuve.
- Une alerte n'est pas une preuve d'attaque : c'est un point à vérifier.
- Ordre de tri : sévérité décroissante, puis horodatage croissant.

Sévérités : **ÉLEVÉE** = action immédiate, **MOYENNE** = à vérifier dans la journée, **FAIBLE** = contexte à confronter.

