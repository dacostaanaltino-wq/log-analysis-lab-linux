# Les règles de détection

Une règle par section : **ce qu'elle détecte**, **pourquoi**, **le seuil**,
**ses limites et faux positifs**, la **sévérité** produite et le lien
**MITRE ATT&CK**.

## Échelle de sévérité

| Sévérité | Signification | Délai de réaction attendu |
|---|---|---|
| **ÉLEVÉE** (`high`) | Compromission probable ou privilèges obtenus | Immédiat |
| **MOYENNE** (`medium`) | Anomalie nette, à confirmer | Le jour même |
| **FAIBLE** (`low`) | Signal de contexte, à confronter aux autres | Quand c'est possible |

## Vue d'ensemble

| Règle | Détecte | MITRE | Sévérité | Seuil par défaut |
|---|---|---|---|---|
| `ssh_brute_force` | Échecs de mot de passe SSH répétés depuis une IP | T1110 | moyenne puis élevée | 5 en 10 min |
| `ssh_user_enumeration` | Noms de comptes différents depuis une IP | T1087 | moyenne | 5 comptes en 10 min |
| `ssh_success_after_failures` | Succès après des échecs depuis la même IP | T1078 | élevée | 4 échecs puis succès |
| `sudo_abuse` | Échecs sudo répétés, sudo sans droit | T1548.003 | moyenne / élevée | 3 en 10 min |
| `account_creation` | Création de compte, ajout à un groupe privilégié | T1136 | moyenne / élevée | 1 événement |
| `service_restart_loop` | Service qui redémarre en boucle | — | moyenne puis élevée | 3 en 10 min |
| `selinux_denied` | Refus SELinux regroupés par processus | — | faible puis moyenne | 1 processus |
| `login_unusual_hours` | Connexion réussie hors horaires de travail | — | faible | 1 connexion |

---

## 1. `ssh_brute_force` — force brute SSH

**Détecte.** Au moins 5 lignes `Failed password for <compte>` depuis la **même
adresse IP** dans une fenêtre de 10 minutes.

**Pourquoi.** C'est l'attaque la plus banale contre un service SSH exposé. Elle
précède souvent la compromission d'un compte à mot de passe faible.

**Seuil.** `--threshold 5` (défaut) et `--window 10`. La sévérité passe à
**élevée** dès `2 × seuil` (10 échecs), ce qui distingue une erreur de script
d'une attaque soutenue.

**Limites et faux positifs.**
- Les lignes `Failed password for invalid user` sont **exclues** : elles
  appartiennent à l'énumération de comptes. Sans cette exclusion, un simple scan
  déclencherait deux règles pour un seul comportement.
- Un mot de passe expiré sur un client automatisé (cron, sauvegarde) peut
  produire exactement ce motif : vérifier la source avant de bloquer.
- Le rapport indique le **pic** (`12 échecs`) et non le premier franchissement
  du seuil (`5`), pour que la gravité réelle soit visible.

**Ce qu'on en fait.** Bloquer l'IP au pare-feu, vérifier qu'aucun compte n'a été
compromis, et imposer les clés SSH (voir le projet
`linux-hardening-lab-fedora`).

---

## 2. `ssh_user_enumeration` — énumération de comptes

**Détecte.** Au moins 5 **noms de comptes différents** depuis la même IP dans la
fenêtre (lignes `Invalid user <nom> from <ip>`).

**Pourquoi.** Un humain ne se trompe pas cinq fois de nom de compte en dix
minutes : c'est un outil qui teste une liste de comptes (`oracle`, `git`, `ftp`…)
avant de cibler les comptes réellement utiles.

**Seuil.** `--min-invalid-users 5`.

**Limites et faux positifs.**
- Un utilisateur qui se trompe de machine et de compte plusieurs fois peut
  déclencher la règle : regarder si le nom ressemble à un prénom ou à un compte
  applicatif.
- Un même compte mal orthographié ne déclenche rien (il faut des noms
  **différents**) : c'est volontaire.

---

## 3. `ssh_success_after_failures` — succès après échecs

**Détecte.** Une authentification réussie (`Accepted …`) depuis une IP qui vient
d'accumuler au moins 4 échecs dans les 10 minutes.

**Pourquoi.** C'est **l'indicateur le plus fort du jeu de règles** : quelqu'un a
trouvé un mot de passe valide. Le compte doit être considéré comme compromis
jusqu'à preuve du contraire.

**Seuil.** `--failures-before-success 4`.

**Limites et faux positifs.**
- Un utilisateur qui se trompe trois fois de mot de passe puis réussit ne
  déclenche rien (seuil à 4) : c'est le cas normal, et c'est volontaire.
- Le succès par clé (`Accepted publickey`) déclenche aussi la règle. Sur un
  serveur où les clés sont la seule méthode, ce serait un faux positif
  permanent — assurez-vous d'avoir coupé `PasswordAuthentication` (projet 2).
- Le message rédigé parle de « compromission » : en lab, vérifiez toujours s'il
  s'agit de votre propre test.

---

## 4. `sudo_abuse` — abus de `sudo`

**Détecte.** Deux signaux distincts :
1. au moins 3 `incorrect password attempt` pour le même utilisateur (`--sudo-failures 3`) ;
2. une ligne `user NOT in sudoers` → alerte **élevée** avec un seul événement.

**Pourquoi.** Le mot de passe `sudo` est une cible privilégiée : qui l'obtient
devient `root`. Et un utilisateur qui tente `sudo` sans y avoir droit n'est pas
une faute de frappe, c'est une tentative d'escalade (T1548.003).

**Limites et faux positifs.**
- Un administrateur pressé peut taper trois fois de travers : le rapport
  indique l'utilisateur, à vous de juger.
- La détection lit les lignes dont `SYSLOG_IDENTIFIER` vaut `sudo` ou qui
  contiennent ` : TTY=`. Si un site a renommé le journal sudo, adapter le
  motif.

---

## 5. `account_creation` — création de compte / privilèges

**Détecte.** Les lignes `useradd`, `usermod`, `groupadd`, `gpasswd`, `userdel`,
`new user: name=…`, `add '<x>' to group '<y>'`, et la clé `auditd` `user_change`.
**Une alerte par événement** (créer un compte est légitime une fois, l'ajouter
à `wheel` ne l'est pas).

**Pourquoi.** La persistance la plus simple pour un attaquant : se créer un
compte, ou se mettre dans `wheel` pour disposer de `sudo` (T1136).

**Sévérité.** Moyenne pour une création, **élevée** si le message mentionne
`wheel` ou `sudo`.

**Limites et faux positifs.**
- Une gestion de parc normale (Ansible, script d'arrivée d'un salarié) génère
  beaucoup d'alertes. La bonne réponse n'est pas de supprimer la règle mais de
  l'exécuter dans la fenêtre de maintenance attendue, ou d'exclure le compte
  d'automatisation.
- Le rattachement à une « fenêtre de maintenance » n'est pas implémenté : c'est
  une amélioration listée dans le README.

---

## 6. `service_restart_loop` — service qui redémarre en boucle

**Détecte.** Au moins 3 lignes `Started <unité>.service` pour la même unité dans
la fenêtre (`--restart-loop 3`).

**Pourquoi.** Un service qui boucle est un problème de disponibilité, et parfois
le symptôme d'autre chose (disque plein, fichier supprimé, service tué par un
attaquant qui échoue).

**Limites et faux positifs.**
- Un service mis à jour par `dnf` peut être relancé plusieurs fois.
- Les unités `*.socket`, `*.scope` et `*.timer` ne sont pas analysées, seulement
  les `*.service`.

---

## 7. `selinux_denied` — refus SELinux

**Détecte.** Les lignes `avc: denied`, regroupées par processus (`comm="…"`).
Sévérité **faible** en dessous de 3 refus, **moyenne** au-delà.

**Pourquoi.** Le refus n'est pas l'attaque : c'est la **preuve que SELinux a
bloqué** quelque chose. Un processus inattendu (`nc`, `perl`, `python`) qui se
fait refuser un accès mérite un coup d'œil.

**Limites et faux positifs.**
- Après une mise à jour, des refus apparaissent en masse pour de mauvaises
  étiquettes : rien à voir avec une attaque.
- Ne jamais « résoudre » le problème en passant SELinux en `permissive`.

---

## 8. `login_unusual_hours` — connexions hors horaires

**Détecte.** Une authentification réussie en dehors de la plage définie
(`--business-hours 8-19`, `--tz Europe/Paris`).

**Pourquoi.** Signal faible mais utile : une connexion réussie à 3 h du matin
sur un compte administratif est rarement légitime.

**Limites et faux positifs.**
- Les astreintes, les voyages et les équipes réparties sur plusieurs fuseaux
  produisent des faux positifs. C'est pourquoi la sévérité est **faible**.
- Par défaut, l'analyse travaille en UTC : passer `--tz Europe/Paris` pour
  raisonner à l'heure locale (nécessite la base de fuseaux du système,
  paquet `tzdata`).

---

## Chevauchements entre règles (assumés)

| Situation | Règles déclenchées | Lecture |
|---|---|---|
| Scan de comptes | `ssh_user_enumeration` (+ `ssh_brute_force` si le scan essaie aussi des mots de passe sur des comptes existants) | Un seul comportement, deux angles : c'est normal |
| Compromission à 3 h du matin | `ssh_success_after_failures` + `login_unusual_hours` | La gravité est portée par la première |
| Création de compte pendant une attaque | `account_creation` + `ssh_*` | À corréler : c'est le scénario de persistance |

Le rapport présente les alertes triées : la première ligne est la plus grave.

## Limites générales de l'outil

- Détection **par règles**, pas d'apprentissage : ce qui n'est pas décrit ne
  sera pas vu. Un compte compromis par un utilisateur légitime ne déclenche rien.
- Analyse **hors ligne** : ce n'est pas un IDS. Il n'y a pas de temps réel.
- L'absence d'alerte ne prouve pas l'absence d'attaque.
- Les seuils par défaut sont calibrés sur le jeu synthétique ; sur une vraie
  machine, il faut les ajuster après quelques jours d'observation (sinon :
  fatigue d'alerte).
