<p align="right">
  <a href="FRAMEWORK.md">English</a> | <b>Français</b>
</p>

# SocketForge — Spécification & Documentation IA du Framework

Ce document est le manifeste technique destiné à l'agent IA et aux développeurs. Il récapitule l'ensemble des capacités, composants et contrats publics exposés par **SocketForge**.

---

## 🎯 Périmètre & Responsabilité

SocketForge est le framework partagé .NET d'**observation, d'énumération et d'analyse des flux et sockets réseau (TCP/UDP) actifs au niveau système (Windows & Linux)**, sans installation de pilote tiers ni dépendance Npcap/WinPcap.

---

## 🚀 Capacités Clés

* **Zéro Npcap** :
  * Windows : inspection via l'API Win32 IP Helper (`iphlpapi.dll` : `GetExtendedTcpTable`, `GetExtendedUdpTable`), pour les sockets IPv4 (`AF_INET`) et IPv6 (`AF_INET6`) ; les adresses IPv6 de lien local gardent leur identifiant de portée (`fe80::1%12`). Une table qui grossit entre l'appel de taille et l'appel de lecture est relue avec la nouvelle taille ; toute autre erreur de l'API lève `Win32Exception` au lieu de rendre un balayage vide.
  * Linux : inspection via le pseudo-système `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` et corrélation des inodes de sockets dans `/proc/<pid>/fd`.
  * Les pairs IPv4 des sockets double pile (`::ffff:a.b.c.d`) sont rendus en adresses IPv4 sur les deux plateformes : un hôte garde une seule adresse.
* **Résolution de direction de flux (`SocketFlowDirectionResolver`)** :
  * Détection précise et cohérente des directions `Listening`, `Inbound` et `Outbound` sur Windows et Linux.
  * Indexation des sockets d'écoute locale (`LISTEN` / `0A` / State 2) pour qualifier formellement les connexions entrantes vers un service hébergé (SSH, HTTP, bases de données, etc.).
  * Heuristiques de repli fondées sur les plages dynamiques/éphémères (Linux `>= 32768`, IANA `>= 49152`) et privilégiées (`< 1024`).
* **Corrélation Processus** :
  * Liaison directe de chaque socket active au processus propriétaire résolu via **`ProcessForge`**.
  * Chaque scan résout une seule fois chaque PID distinct, quel que soit le nombre de sockets du processus (depuis 2.1.0, Windows et Linux).
  * `SocketScannerFactory.Create()` (depuis 2.1.0) construit le scanner avec un `CachingProcessInspector` de ProcessForge autour d'un `CrossPlatformProcessInspector`, conservé pendant toute la vie du scanner : un processus déjà vu n'est pas relu aux scans suivants tant que son heure de démarrage ne change pas. Garder un seul scanner tant que l'on scanne.
  * `SocketScannerFactory.Create(IProcessInspector)` utilise l'inspecteur fourni tel quel, sans y ajouter de cache.
* **Typage fort & Clé d'unicité logique** :
  * Modélisation immuable (`ActiveSocketConnection`, `SocketEndpoint`, `SocketTransportProtocol`, `SocketFlowDirection`).
  * Clé de dédoublonnage canonique préservant l'identité applicative des flux sortants indépendamment des ports locaux éphémères.
  * La partie propriétaire de la clé est l'exécutable cible, sinon le chemin de l'exécutable, sinon le nom du processus (depuis 2.0.0) : les processus dont le chemin est illisible ne sont plus fusionnés en un seul flux. Rupture de compatibilité : les clés des flux dont le chemin était vide diffèrent de celles écrites par 1.x.
* **Les sockets TIME_WAIT sans propriétaire ne sont pas rendus** (depuis 2.0.0) : un socket TCP (IPv4 ou IPv6) en TIME_WAIT détenu par le pid 0 sous Windows, ou d'inode 0 sous Linux, n'appartient plus à aucun processus et apparaîtrait sinon comme un second flux vers la même destination.

---

## 📋 Protocole de Maintenance par l'Agent IA

Toute modification de SocketForge doit respecter :
1. **Rétrocompatibilité :** Conserver tous les contrats publics existants. Utiliser des surcharges ou des paramètres optionnels.
2. **Qualité :** Zéro warning (`<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`), zéro pragma/suppress.
3. **Tests :** Nommage `MethodeCible_ScenarioOuCondition_ResultatAttendu`.
4. **Mise à jour :** Compléter immédiatement ce fichier `FRAMEWORK.md` en cas d'ajout d'une nouvelle capacité.
5. **Validation :** Valider par `./verify.ps1`.
