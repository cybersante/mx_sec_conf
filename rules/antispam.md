# Mise en place d'une solution AntiSpam
Tests ACSS concernés n°: 5, 6, 7  
Date Creation: 18/09/2020  
Date dernière mise à jour: 18/09/2020  
Facilité de mise en place: Simple ~~/ Moyen / Complexe~~  

Les exemples de configuration (ci-dessous) sont basés sur rspamd (https://rspamd.com/).  
Si vous ne souhaitez pas utiliser RSPAMD, vous pouvez vous en inspirer pour l'adapter à votre solution de protection de messagerie.

1. [Let's get started!](#instal)
2. [Ce que nous avons ajouté ou configuré dans RSPAMD](#add)

##  Let's get started! <a name="instal"></a>
Attention, cette documentation n'a pas pour objectif de vous expliquer en detail les possibilités offertent par Rspamd.  
Pour ce faire, nous vous invitons à aller sur leur site (https://rspamd.com/doc/configuration/index.html) et à lire le retour d'experience de Monsieur G. CATTEAU au JRES 2019 (https://conf-ng.jres.org/2019/document_revision_4778.html?download).  

### Installation
#### Docker
Le plus simple pour installer RSPAMD est d'utiliser un docker qui emportera l'ensemble des éléments nécéssaires à son bon fonctionnement (redis, olefy, clamav, ...).  
Si vous ne connaissez pas encore la technologie docker, il est temps de s'y mettre: https://www.docker.com/ .  
Nous vous proposons une configuration RSPAMD modifiée en provenance de la messagerie "Mailcow" (https://github.com/mailcow/mailcow-dockerized), mais vous restez libre d'utiliser une autre source (il en existe beaucoup sur github):
 - [Docker-compose Rspamd](rules/antispam.md)
#### Package
Rspamd est disponible sur les principales distributions linux (https://rspamd.com/downloads.html). Cependant il faudra installer les outils annexes aussi (redis, clamav, ...).
### Fonctionnalités
Comme indiqué plus haut, je vous donne la majorité des fonctionnalités du produit Rspamd (version 2.6) sans rentrer dans le detail, pour plus d'informations suivez le lien...  
  
Petites informations importantes à savoir sur les options générales ('override.d/worker-normal.inc') :
  - Un module ou une tache de verification que vous allez programmer à un temps maximum pour s'executer (par défaut 8s), mais certaines taches demandes plus. Vous pouvez changer cela avec la variable "task_timeout".
  - Un courriel ne peut pas générer plus de 64 requètes DNS (par défaut). Vous pouvez augmenter cette valeur avec la variable "dns_max_requests".
#### Scores, Actions, Symboles et Combinaisons
Rspamd offre des règles internes (définies par des symboles 'SYMBOLS' que vous pouvez retrouver sur l'interface graphique de RSPAMD en haut afin d'identifier l'ensemble des possibilités offertent par défaut). Il est possible dans le fichier "local.d/composites.conf" de créer des règles en combinant des 'SYMBOLS'. Vous pouvez aussi créer des symboles pour générer de nouvelles règles, ces nouveaux symboles seront alors visibles dans l'interface graphique de RSPAMD.

Pour chaque symbole on définie un score. Si le courriel déclenche un symbole (donc une règle) alors il ajoute le score de ce symbole au score déjà obtenu par le courriel. Si le score atteint les limites fixées dans "local.d/action.conf" alors il effectuera l'action indiquée.
Pour plus d'informations: 
  - https://rspamd.com/doc/configuration/composites.html
  - https://rspamd.com/doc/configuration/metrics.html

#### Les modules
Vous pourrez trouver les configurations par default de RSPAMD sur github: https://github.com/rspamd/rspamd/tree/master/conf .  

  - **Antivirus**: 
    - Description: scan par antivirus
    - Activation: la configuration Docker propose l'integration avec Clamav
    - Symbole de resultat: "CLAM_VIRUS*"
    - Fichier de configuration: "local.d/antivirus.conf"
    - Risque de faux positifs: Oui, en lien avec les signatures activées (official == risque faible)
    - utilisation services externes:
       - REDIS: Non
    - Réference: https://rspamd.com/doc/modules/antivirus.html
  - **ARC**: "Authenticated Received Chain" DKIM (https://rspamd.com/doc/modules/arc.html)
    - Description: "Authenticated Received Chain" DKIM
    - Fichier de configuration: "local.d/arc.conf"
    - Activation: Oui
    - Risque de faux positifs: Non
    - utilisation services externes:
       - REDIS: Oui
    - Réference: https://rspamd.com/doc/modules/arc.html
  - **ASN**: 
    - Description: Récuperation d'informations sur l'adresse IP => ANS, Subnet, Pays; pour être utilisées par les autres modules.
    - Fichier de configuration: "local.d/asn.conf"
    - Activation: Oui
    - Risque de faux positifs: Aucun, pas d'action directe
    - utilisation services externes:
      - REDIS: Non
      - Serveur RSPAMD: asn.rspamd.com & asn6.rspamd.com
    - Réference: https://rspamd.com/doc/modules/asn.html
  - **Bayes**: 
    - Description: Netoyages des statistiques balaysiennes
    - Fichier de configuration: "local.d/statistic.conf" (depuis la version 2.0)
    - Activation: Oui
    - Risque de faux positifs: Aucun pas, d'action directe
    - utilisation services externes:
      - REDIS: oui
    - Réference: https://rspamd.com/doc/modules/bayes_expiry.html
  - **Clickhouse**: 
    - Description: Permet de créer un tableau de bord sur une base "clickhouse" afin d'analyser les statistiques générées par RSPAMD.
    - Fichier de configuration: "local.d/clickhouse.conf"
    - Activation: Oui
    - Risque de faux positifs: Aucun, pas d'action directe
    - utilisation services externes: 
      - Clickhouse: https://clickhouse.tech/#quick-start
    - Réference: https://rspamd.com/doc/modules/clickhouse.html
  - **Chartable**: 
    - Description: Il regarde dans chaque mot s'il y a beaucoup de transitions entre des lettres en ASCII et non ASCII.
    - Symbole de resultat: "R_MIXED_CHARSET"
    - Fichier de configuration: "local.d/chartable.conf" (pour désactiver: "enabled = false;")
    - Activation: Oui par defaut
    - Risque de faux positifs: Oui, très faible mais seulement sur des langues particulières
    - utilisation services externes: Aucun
    - Réference: https://rspamd.com/doc/modules/chartable.html  
  - **DCC**:
    - Description: DCC identifie via le checksum d'un message transmis à leur serveur si le message à été transmis en masse ou non.
    - Symbole de resultat: "DCC_\*"
    - Fichier de configuration: "local.d/dcc.conf" 
    - Activation: Non
    - Risque de faux positifs: Oui, une campagne de pub pourrait être considérée comme un spam car de nombreux utilisateurs vont recevoir le même courriel. Si vous l'activez, limitez le score des symboles "DCC_\*" afin d'eviter des faux positifs
    - utilisation services externes:
      - Dockerfile DCC possible: https://github.com/Neomediatech/dcc-docker/blob/master/Dockerfile
      - Utilise les ressources des serveurs DCC: https://www.dcc-servers.net/dcc/#public-servers
    - Réference: https://rspamd.com/doc/modules/dcc.html  
  - **DKIM**: 
    - Description: il verifie la validité de la signature DKIM d'un message.
    - Activation: Oui par defaut
    - Risque de faux positifs: Non connu
    - utilisation services externes: Aucun
    - Réference: https://rspamd.com/doc/modules/dkim.html 
  - **DKIM signing**: 
    - Description: Il signe les messages avec la clé DKIM selon des règles définies
    - Fichier de configuration: "local.d/dkim_signing.conf"
    - Activation: Non (vous devez avoir une clé DKIM pour l'activer; clé publique dans le DNS)
    - Risque de faux positifs: Aucun car c'est un module qui ajoute une signature dans vos courriels sortants
    - utilisation services externes: Aucun
    - Réference: https://rspamd.com/doc/modules/dkim_signing.html
  - **DMARC**: 
    - Description: DMARC est une technologie exploitant SPF & DKIM qui permet aux propriétaires de domaine de publier des politiques concernant la manière dont les messages portant leur domaine (FROM) doivent être traités et choisir de recevoir des informations de rapport sur ces messages.
    - Symboles:
      - DMARC_BAD_POLICY: Policy was invalid or multiple policies found in DNS
      - DMARC_NA: Domain in From header has no DMARC policy or From header is missing
      - DMARC_POLICY_ALLOW: Message was authenticated & allowed by DMARC policy
      - DMARC_POLICY_REJECT: Authentication failed- rejection suggested by DMARC policy
      - DMARC_POLICY_QUARANTINE: Authentication failed- quarantine suggested by DMARC policy
      - DMARC_POLICY_SOFTFAIL: Authentication failed- no action suggested by DMARC policy
    - Fichier de configuration: "local.d/dmarc.conf" 
    - Activation: Oui par defaut (rapport desactivé)
    - Risque de faux positifs: Non connu
    - utilisation services externes:
      - REDIS: oui pour rapport
    - Réference: https://rspamd.com/doc/modules/dmarc.html
  - **Elasticsearch**: 
    - Description: Permet de créer un tableau de bord sur une base "elasticsearch via kibana" afin d'analyser les statistiques générées par RSPAMD.
    - Fichier de configuration: "local.d/elastic.conf"
    - Activation: Non
    - Risque de faux positifs: Aucun, pas d'action directe
    - utilisation services externes: 
      - elasticsearch
    - Réference: https://rspamd.com/doc/modules/elastic.html
  - **External Services**: 
    - Description: Permet d'integrer l'analyse d'outils exterieurs (oletools, pyzor, razor, virustotal, ,...)
    - Fichier de configuration: "local.d/external_services.conf"
    - Activation: Oui pour oletools
    - Risque de faux positifs: Oui si des utilisateurs exterieurs s'échangent des documents Office avec du contenu "macro", mieux vaut eviter d'autoriser cela dans tous les cas.
    - utilisation services externes: 
      - Olefy (integré au docker)
      - Possibilité de créer son module externe, exemple: https://github.com/Neomediatech/rspamd/blob/master/conf/plugins.d/pyzor.lua
    - Réference: https://rspamd.com/doc/modules/external_services.html
  - **Force actions**: 
    - Description: Permet de forcer une action lors du déclenchement d'un symbole.
    - Fichier de configuration: "local.d/force_actions.conf"
    - Activation: Oui
    - Risque de faux positifs: Oui, il y a toujours un risque si vous forcez en rejet sur un symbole...
    - utilisation services externes:
    - Réference: https://rspamd.com/doc/modules/force_actions.html
  - **Fuzzy check**: 
    - Description: Permet d'identifier des courriels très sembables (fuzzyhash) en local ou dans la base bl.rspamd.com
      - Plusieurs possibilités d'utilisation en local (https://rspamd.com/doc/fuzzy_storage.html):
        - Utilisation de boites "pot de miel";
        - Utilisation de spam transmis par vos utilisateurs ou lors de campagne massive qui dure...
    - Fichier de configuration: "local.d/fuzzy_check.conf"
    - Activation: Oui
    - Risque de faux positifs: Oui, mais très faible car cela voudrait dire que de nombreuses personnes considèrent le contenu d'une campagne comme indesirable mais pas vous. 
    - utilisation services externes:
      - Redis ("override.d/worker-fuzzy.inc") - Symboles: (LOCAL_FUZZY_DENIED, LOCAL_FUZZY_PROB, LOCAL_FUZZY_WHITE, LOCAL_FUZZY_UNKNOWN)
      - bl.rspamd.com (Symboles: FUZZY_DENIED, FUZZY_PROB, FUZZY_WHITE, FUZZY_UNKNOWN)
    - Réference: https://rspamd.com/doc/modules/fuzzy_check.html
  - **Fuzzy collect**: 
    - Description: Collecte de fuzzy hash en provenance d'autres instances afin de les propager dans le cluster
    - Fichier de configuration: "local.d/fuzzy_check.conf"
    - Activation: Oui
    - Risque de faux positifs: Aucun, pas d'action directe
    - utilisation services externes:
      - Redis ("override.d/worker-fuzzy.inc") - Symboles: (LOCAL_FUZZY_DENIED, LOCAL_FUZZY_PROB, LOCAL_FUZZY_WHITE, LOCAL_FUZZY_UNKNOWN)
      - bl.rspamd.com (Symboles: FUZZY_DENIED, FUZZY_PROB, FUZZY_WHITE, FUZZY_UNKNOWN)
    - Réference: https://rspamd.com/doc/modules/fuzzy_collect.html
  - **Greylisting**: 
    - Description: https://fr.wikipedia.org/wiki/Greylisting
    - Fichier de configuration: "local.d/greylist.conf"
    - Activation: Oui
    - Risque de faux positifs: Oui, mais très faible car vous rejetez que temporairement le courriel. Le seul risque est d'avoir une campagne de courriels légitimes transmis par un tiers qui n'utilise pas un serveur de messagerie et dont le script d'envoi ne sera pas traiter la demande d'attente de renvoi (dans ce cas mieux vaut indiquer à ce tiers d'utiliser correctement le protocole de messagerie).
    - utilisation services externes:
      - Redis 
    - Réference: https://rspamd.com/doc/modules/greylisting.html
  - **Hfilter**: 
    - Description: Verification DNS sur les éléments: from, rcpt, mid, helo, url.
    - Symboles: recherche 'hfilter' dans l'interface web/symbols.
    - Fichier de configuration: "local.d/hfilter.conf"
    - Activation: Oui
    - Risque de faux positifs: Configurer les scores de manière juste.
    - utilisation services externes:
      - Requetes DNS
    - Réference: https://rspamd.com/doc/modules/hfilter.html
  - **Redis history**: 
    - Description: Stock l'historique dans redis afin de pouvoir l'analyser dans l'interface web (limite en profondeur).
    - Fichier de configuration: "local.d/history_redis.conf"
    - Activation: Oui
    - Risque de faux positifs: Aucun, pas d'action directe
    - utilisation services externes:
      - Redis 
    - Réference: https://rspamd.com/doc/modules/history_redis.html
  - **mail list**: 
    - Description: Identifie si le courriel est une mailling list afin de désactiver certaines verifications non adaptées.
    - Fichier de configuration: Aucun
    - Activation: Oui
    - Risque de faux positifs: Non au contraire limite le risque de faux positif sur les maillings list.
    - utilisation services externes: non
    - Réference: https://rspamd.com/doc/modules/maillist.html
  - **Metadata exporter**: 
    - Description: Permet de transmettre un courriel vers un service/application tiers sur des courriels identifiés comme interessants.
      - Par exemple on peut vouloir transmettre les courriels bloqués par l'antivirus vers une quarantaine pour analyse.
    - Fichier de configuration: "local.d/metadata_exporter.conf"
    - Activation: Non (à définir selon votre contexte)
    - Risque de faux positifs: Aucun, pas d'action directe
    - utilisation services externes: 
      - potentiellement oui selon ce que vous souhaitez faire.
    - Réference: https://rspamd.com/doc/modules/metadata_exporter.html
  - **Metadata exporter**: 
    - Description: Permet de transmettre un courriel vers un service/application tiers sur des courriels identifiés comme interessants.
      - Par exemple on peut vouloir transmettre les courriels bloqués par l'antivirus vers une quarantaine pour analyse.
    - Fichier de configuration: "local.d/metadata_exporter.conf"
    - Activation: Non (à définir selon votre contexte)
    - Risque de faux positifs: Aucun, pas d'action directe
    - utilisation services externes: 
      - potentiellement oui selon ce que vous souhaitez faire.
    - Réference: https://rspamd.com/doc/modules/metadata_exporter.html
  - **MID**: 
    - Description: Il permet de supprimer les symboles "INVALID_MSGID" et "MISSING_MID" lorsqu'un message est signé par DKIM
    - Fichier de configuration: "local.d/mid.conf"
    - Activation: Oui
    - Risque de faux positifs: Aucun, pas d'action directe
    - utilisation services externes: non
    - Réference: https://rspamd.com/doc/modules/mid.html
  - **MID**: 
    - Description: Il permet de supprimer les symboles "INVALID_MSGID" et "MISSING_MID" lorsqu'un message est signé par DKIM
    - Fichier de configuration: "local.d/mid.conf"
    - Activation: Oui
    - Risque de faux positifs: Aucun, pas d'action directe
    - utilisation services externes: non
    - Réference: https://rspamd.com/doc/modules/mid.html
  - **Milter Headers**: 
    - Description: Permet d'ajouter et/ou supprimer des en-têtes d'un courriels.
    - Fichier de configuration: "local.d/milter_headers.conf"
    - Activation: Oui
    - Risque de faux positifs: Aucun, pas d'action de score ou rejet.
    - utilisation services externes: non
    - Réference: https://rspamd.com/doc/modules/milter_headers.html
  - **Mime types**: 
    - Description: Permet de verifier:
       - si le mime type est dans la liste "maps.d/mime_types.inc" => Symbole: MIME_GOOD/MIME_BAD/MIME_UNKNOWN
       - si une piece jointe à l'extension en relation avec son "mime-type" => Symbole: 	MIME_BAD_ATTACHMENT
       - si c'est une archive verifie à l'interieur que les types de fichiers présents => MIME_ARCHIVE_IN_ARCHIVE
       - si il contient un pattern suspect (type: "document.doc.exe") => MIME_DOUBLE_BAD_EXTENSION/MIME_BAD_UNICODE
       - une politique personnalité (interdire les executables) => MIME_BAD_EXTENSION
    - Fichier de configuration: "local.d/mime_types.conf"
    - Activation: Oui
    - Risque de faux positifs: Oui si quelqu'un vous transmet un piece jointe non autorisée par votre politique (si on peut appeler ca un faux positif...).
    - utilisation services externes: non
    - Réference: https://rspamd.com/doc/modules/mime_types.html
  - **Multimap**: 
    - Description: Manipule les règles basées sur des listes qui sont mises à jour automatique via differents protocoles (http/https/resp/local/cdb) dont le contenu peut être varié (https://rspamd.com/doc/modules/multimap.html#map-types)
    - Fichier de configuration: "local.d/multimap.conf"
    - Activation: Oui
    - Risque de faux positifs: Oui selon les règles mises en place
    - utilisation services externes: 
      - Oui si la ressource est exterieur
    - Réference: https://rspamd.com/doc/modules/multimap.html
  - **MX check**: 
    - Description: Verification que l'expediteur à un MX valide
    - Symboles: MX_INVALID/MX_MISSING/MX_GOOD/MX_WHITE
    - Fichier de configuration: "local.d/mx_check.conf"
    - Activation: Oui
    - Risque de faux positifs: Aucun, car un expediteur doit avoir un MX valide
    - utilisation services externes: 
      - Redis
    - Réference: https://rspamd.com/doc/modules/mx_check.html
  - **Neural Network**: 
    - Description: Apprend les SPAM et HAM par reseau neuronal pour faire de la post-classification en fonction des symboles obtenus et des apprentisages précédents.
    - Symboles: NEURAL_SPAM_LONG/NEURAL_SPAM_SHORT/NEURAL_HAM_LONG/NEURAL_HAM_SHORT
    - Fichier de configuration: "local.d/neural.conf"
    - Activation: Oui
    - Risque de faux positifs: Non connu
    - utilisation services externes: 
      - Redis
    - Réference: https://rspamd.com/doc/modules/neural.html
  - **Phishing check**: 
    - Description: permet plusieurs verifications:
      - l'url dans un courriel pointe sur le meme domaine que celui visible => symbole: PHISHING
      - l'url est connu dans une liste noire => symboles: PHISHED_PHISHTANK/PHISHED_OPENPHISH/PH_SURBL_MULTI
      - l'url contient un chemin qui semble indiquer que le site est potentiellement compromis => symbole: 	HACKED_WP_PHISHING
    - Fichier de configuration: "local.d/phishing.conf"
    - Activation: Oui
    - Risque de faux positifs: Oui si une personne indique une URL visible avec une URL réelle contenant un domaine different (mais cela est une très mauvaise pratique).
    - utilisation services externes: 
      - base de Threat Intel (phishtank, openphish, surbl)
    - Réference: https://rspamd.com/doc/modules/phishing.html
  - **Rate limit**: 
    - Description: Permet de limiter le nombre de message en provenance d'un expediteur.
    - Fichier de configuration: "local.d/ratelimit.conf"
    - Activation: Non
    - Risque de faux positifs: Oui si un expediteur commence a transmettre beaucoup de courriel dans un laps de temps court.
    - utilisation services externes:
      - redis
    - Réference: https://rspamd.com/doc/modules/ratelimit.html
  - **RBL**: 
    - Description: Verifie les éléments d'un courriel (ip, email, header, ...) par rapport à des RBL externes (sorbs, spamhaus, ...).
    - Symboles: il y en a beaucoup donc regardez sur l'interface web par une recherche sur 'rbl'
    - Fichier de configuration: "local.d/rbl.conf"
    - Activation: Oui
    - Risque de faux positifs: Oui si un expediteur légitime est en liste noire, mais normalement son service informatique fera le nécéssaire rapidement.
    - utilisation services externes: 
      - RBL externes
    - Réference: https://rspamd.com/doc/modules/rbl.html
  - **Regexp**: 
    - Description: filtrage des messages par regexp, fonctions internes et code LUA.
    - Fichier de configuration: "lua/rspamd.local.lua"
    - Activation: Oui
    - Risque de faux positifs: Selon la règle
    - utilisation services externes: selon la règle
    - Réference: https://rspamd.com/doc/modules/regexp.html
  - **Reputation**: 
    - Description: Verifie la réputation de certains objects contenus dans le courriel et ajuste le score.
    - Fichier de configuration: 
      - "local.d/reputation.conf"
      - "local.d/url_reputation.conf"
      - "local.d/ip_score.conf"
    - Activation: Oui
    - Risque de faux positifs: NC
    - utilisation services externes: 
      - Redis
    - Réferences: 
      - https://rspamd.com/doc/modules/reputation.html
      - https://rspamd.com/doc/modules/url_reputation.html
      - https://rspamd.com/doc/modules/ip_score.html
  - **Received policy**: 
    - Description: Vérifie dans l'en-tête "received" la présence de mots-clé suspects comme "dynamic" qui pourraient indiquer la compromission d'un compte.
    - sumboles: ONCE_RECEIVED_STRICT/ONCE_RECEIVED
    - Fichier de configuration: "local.d/once_received.conf"
    - Activation: Oui
    - Risque de faux positifs: Oui si dans receive il y a des mots-clés (faible)
    - utilisation services externes:  non
    - Réference: https://rspamd.com/doc/modules/once_received.html
  - **Replies mode**: 
    - Description: permet d'identifier si le courriel contient une réponse à un courriel transmis par un utilisateur interne afin d'ameliorer le score.
    - Symbole: REPLY
    - Fichier de configuration: "local.d/replies.conf"
    - Activation: Oui
    - Risque de faux positifs: 
    - utilisation services externes: 
    - Réference: https://rspamd.com/doc/modules/replies.html
  - **SpamAssassin rules**: 
    - Description: Réutilisation de règle spamassassin en natif dans rspamd.
    - Fichier de configuration: 
      - "local.d/spamassassin.conf"
      - "custom/sa-rules"
    - Activation: Oui
    - Risque de faux positifs: Oui selon les règles.
    - utilisation services externes: Non
    - Réference: https://rspamd.com/doc/modules/spamassassin.html
  - **SpamTrap**: 
    - Description: Permet d'extraire des spams pour les apprendre et les filtrer selon l'adresse courriel ou le domaine.
    - Fichier de configuration: 
      - "local.d/spamtrap.conf"
      - "maps.d/spamtrap.map" ou redis
    - Activation: Non
    - Risque de faux positifs: Selon votre regexp
    - utilisation services externes: 
      - redis si pas d'utilisation de map
    - Réference: https://rspamd.com/doc/modules/spamtrap.html
  - **SPF**: 
    - Description: Vérification de la légitimité du serveur d'expedition pour le domaine via SPF (https://fr.wikipedia.org/wiki/Sender_Policy_Framework)
    - Symboles: R_SPF_FAIL/R_SPF_NEUTRAL/R_SPF_SOFTFAIL/R_SPF_ALLOW/R_SPF_DNSFAIL
    - Fichier de configuration: "local.d/spf.conf"
    - Activation: Oui
    - Risque de faux positifs: Aucun car il respecte les intructions de l'expediteur (son enregistrement SPF), si malgré tout votre expediteur n'est pas doué, vous pouvez ajouter son adresse IP en liste blanche SPF.
    - utilisation services externes: 
      - DNS pour la requete SPF
    - Réference: https://rspamd.com/doc/modules/spf.html
  - **URL redirector**: 
    - Description: Le mode va verifier si l'URL contenu dans un courriel est une redirection (code web 302).
    - Fichier de configuration: "local.d/url_redirector.conf"
    - Activation: Non
    - Risque de faux positifs: Oui, car de nombreuses structures utilisent des outils de statistique qui causent une redirection.
    - utilisation services externes: 
      - Requete web vers l'URL pour identifier le code (200/302/...)
    - Réference: https://rspamd.com/doc/modules/url_redirector.html
  - **Whitelist**: 
    - Description: permet de monter ou descendre le score selon des listes blanches pour le SPF/DKIM/DMARC.
    - Fichier de configuration: "local.d/whitelist.conf"
    - Activation: Oui
    - Risque de faux positifs: Selon les règles (peut surtout causer du faux négatif).
    - utilisation services externes: Non
    - Réference: https://rspamd.com/doc/modules/whitelist.html
#### Ecrire sa propre règle
Avec RSPAMD, il est très facile d'écrire sa propre règle, pour plus d'informations: https://rspamd.com/doc/tutorials/writing_rules.html
#### Tester vos règles
Afin de tester vos règles et surtout assurer leurs bons fonctionnements, vous pouvez utiliser l'interface graphique avec un courriel qui contient votre contenu à détecter, et vérifier le déclenchement de vos règles.
##### Vous avez déjà un RSPAMD
Pour mettre votre rspamd déjà existant en test, allez dans le fichier "override.d/worker-proxy.inc" et créer un "mirroir":
```
mirror "test" {
  name = "rspamdtest"
  hosts = "IP_DOCKER_RSPAMD:11333";
  probability = 1; # Mirror 100% of traffic
}
```
De plus, vous pouvez ajouter un script afin d'identifier les differences entre votre version stable et celle en test ("override.d/worker-proxy.inc"):
```
  script =<<EOD
return function(results)
  local log = require "rspamd_logger"

  for k,v in pairs(results) do
    if type(v) == 'table' then
      log.errx("%s: %s", k, v['score'])
    else
      log.errx("err: %s: %s", k, v)
    end
  end
end
EOD;
```
##### Vous n'avez pas de RSPAMD
Ajouter RSPAMD dans votre MTA puis afin de voir ces actions, configurez "local.d/actions.conf" avec des scores très élevés:
```
reject = 15000;
add_header = 8000;
greylist = 7000;
```
Cela permettra d'avoir dans les headers de votre courriel les informations RSPAMD mais aussi de pouvoir analyser vos logs (rspamd web, logs, elastic, ...) sans risque de faux positifs.

### Configuration
Comme l'indique Monsieur G. CATTEAU dans son retour d'experience, il est préférable dans un premier temps de mettre RSPAMD en "no action" pour prendre le temps d'identifier les risques de faux positif pouvant engendrer de la perte de courriels légitimes (https://rspamd.com/doc/workers/rspamd_proxy.html#mirroring).
#### Configuration du service REDIS
Dans le fichier "/etc/rspamd/local.d/redis.conf", vous devez configurer votre service REDIS (si vous utilisez le docker, cela est déjà operationnel).
Plus d'informations sur: https://rspamd.com/doc/configuration/redis.html

Ce service est nécéssaire pour que les modules/plugins suivants fonctionnent correctement:
  - ratelimit
  - greylisting
  - Dmarc report
  - IP score
  - Replies
  - Multimap
  - MX check
  - Reputation
  - Neural network
 
#### Configuration de RSPAMD dans le MTA postfix
Vous trouverez dans le lien suivant, les informations pour integrer RSPAMD dans postfix via le protocol milter: https://rspamd.com/doc/workers/rspamd_proxy.html .  
Pensez à tester sans action dans un premier temps (https://rspamd.com/doc/workers/rspamd_proxy.html#mirroring).  
Si vous utilisez notre docker-compose, alors vous pouvez integrer à postfix dans "/etc/postfix/main.cf":
  - si votre docker est sur le meme serveur que postfix: "smtpd_milters = inet:172.17.0.1:9900"
  - si votre docker est sur un autre serveur que postfix: "smtpd_milters = inet:IP-DOCKER:9900" 
    - (pensez à filter le port avec netfilter qu'il ne soit accessible qu'aux IP MX/SMTP)
    - modifier docker-compose.yml en replacant "172.17.0.1:9900:9900" par "9900:9900"

Pour finir, n'oubliez pas de changer le mot de passe de l'interface web dans le fichier "override.d/worker-controller-password.inc" (https://rspamd.com/doc/quickstart.html#setting-the-controller-password).
#### Configuration de RSPAMD dans un autre MTA
Vous trouverez dans le lien suivant, les informations pour integrer RSPAMD dans votre MTA: https://rspamd.com/doc/integration.html .

## Ce que nous avons ajouté ou configuré dans RSPAMD <a name="add"></a>
Les ajoutes ont été realisés sur la version 2.6 de RSPAMD avec la configuration de base "mailcow" (https://github.com/mailcow/mailcow-dockerized/tree/master/data/conf/rspamd).  
### Configuration global du worker "normal"
Afin d'adapter le temps d'analyse de clamav et du module check_url, nous avons monté la valeur "task_timeout".  
De plus, nous avons monté la limite des requetes DNS ("dns_max_requests") qui peuvent devenir importantes avec le module check_url.  
References:
  - https://rspamd.com/doc/workers/normal.html
  - []()
### "local.d/"
Nous avons utilisé la configuration de mailcow et l'avons légèrement modifié pour couvrir l'ensemble des risques.  
Vous pourrez trouver la configuration de chacun des modules/plugins dans le repertoire "local.d".  

### Module check_url
Vous pourrez trouver le module dans le docker présent sur le [dépot](/rspamd-docker/data/patch/rspamd/check_url.lua) ou dans la [PR](https://github.com/rspamd/rspamd/pull/3508).

### Modification de la rules mid.
Vous pourrez trouver le module dans le docker présent sur le [dépot](/rspamd-docker/data/patch/rspamd/mid.lua) ou dans la [PR](https://github.com/rspamd/rspamd/pull/3509).

### Composite

### Rspamd.local.lua

### Score des symboles 
