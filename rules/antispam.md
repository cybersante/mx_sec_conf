# Mise en place d'une solution AntiSpam
Tests ACSS concernés n°: 5, 6, 7
Date Creation: 18/09/2020  
Date dernière mise à jour: 18/09/2020  
Facilité de mise en place: Simple ~~/ Moyen / Complexe~~  

Les exemples de configuration (ci-dessous) sont basés sur rspamd (https://rspamd.com/).  
Si vous ne souhaitez pas utiliser RSPAMD, vous pouvez vous en inspirer pour l'adapter à votre solution de protection de messagerie.

Règles:
1. [Let's get started with Rspamd!](#instal)
2. [GTUBE](#gtube)


##  Let's get started! <a name="instal"></a>
Attention, cette documentation n'a pas pour objectif de vous expliquer en detail les possibilités offertent par Rspamd.  
Pour ce faire, nous vous invitons à aller sur leur site (https://rspamd.com/doc/configuration/index.html) et à lire le retour d'experience de Monsieur G. CATTEAU au JRES 2019 (https://conf-ng.jres.org/2019/document_revision_4778.html?download).  

### Installation
#### Docker
Le plus simple pour installer RSPAMD est d'utiliser un docker qui emportera l'ensemble des éléments nécéssaires à son bon fonctionnement (redis, olefy, clamav, ...).  
Si vous ne connaissez pas encore la technologie docker, il est temps de s'y mettre: https://www.docker.com/ .  
Nous vous proposons une configuration RSPAMD modifié en provenance de la messagerie "Mailcow" (https://github.com/mailcow/mailcow-dockerized), mais vous restez libre d'utiliser une autre source (il en existe beaucoup sur github):
 - [Docker-compose Rspamd](rules/antispam.md)
#### Package
Rspamd est disponible sur les principales distributions linux (https://rspamd.com/downloads.html). Cependant il faudra installer les outils annexes aussi (redis, clamav, ...).
### Fonctionnalités
Comme indiqué plus haut, je vous donne la majorité des fonctionnalités du produit Rspamd (version 2.5) sans rentrer dans le detail, pour plus d'informations suivez le lien...
#### Scores, Actions, Symboles et Combinaisons
Rspamd offre des règles internes (définies par des symboles 'SYMBOLS' que vous pouvez retrouver sur l'interface graphique de RSPAMD en haut afin d'identifier l'ensemble des possibilités offertent par défaut). Il est possible dans le fichier "local.d/composites.conf" de créer des règles en combinant des 'SYMBOLS'. Vous pouvez aussi créer des symboles pour générer de nouvelles règles, ces nouveaux symboles seront alors visibles dans l'interface graphique de RSPAMD.

Pour chaque symbole on définie un score. Si le courriel déclenche un symbole (donc une règle) alors il ajoute le score de ce symbole au score déjà obtenu par le courriel. Si le score atteint les limites fixées dans "local.d/action.conf" alors il effectuera l'action indiquée.
Pour plus d'informations: 
  - https://rspamd.com/doc/configuration/composites.html
  - https://rspamd.com/doc/configuration/metrics.html
#### Les modules
Vous pourrez trouver les configurations par default de RSPAMD sur github: https://github.com/rspamd/rspamd/tree/master/conf .  

  - Antivirus: 
    - Description: scan par antivirus
    - Activation: la configuration Docker propose l'integration avec Clamav
    - Symbole de resultat: "CLAM_VIRUS*"
    - Fichier de configuration: "local.d/antivirus.conf"
    - utilisation:
       - REDIS: Non
    - Réference: https://rspamd.com/doc/modules/antivirus.html
  - ARC: "Authenticated Received Chain" DKIM (https://rspamd.com/doc/modules/arc.html)
    - Description: "Authenticated Received Chain" DKIM
    - Fichier de configuration: "local.d/arc.conf"
    - Activation: Oui
    - utilisation: 
       - REDIS: Oui
    - Réference: https://rspamd.com/doc/modules/arc.html
  - ASN: 
    - Description: Récuperation d'informations sur l'adresse IP => ANS, Subnet, Pays; pour être utilisées par les autres modules.
    - Fichier de configuration: "local.d/asn.conf"
    - Activation: Oui
    - utilisation: 
      - REDIS: Non
      - Serveur RSPAMD: asn.rspamd.com & asn6.rspamd.com
    - Réference: https://rspamd.com/doc/modules/asn.html
  - Bayes: 
    - Description: Netoyages des statistiques balaysiennes
    - Fichier de configuration: "local.d/statistic.conf" (depuis la version 2.0)
    - Activation: Oui
    - utilisation: 
      - REDIS: oui
    - Réference: https://rspamd.com/doc/modules/bayes_expiry.html
  - Clickhouse: 
    - Description: Permet de créer un tableau de bord sur une base "clickhouse" afin d'analyser les statistiques générées par RSPAMD.
    - Fichier de configuration: "local.d/clickhouse.conf"
    - Activation: Oui
    - utilisation: 
      - Clickhouse: https://clickhouse.tech/#quick-start
    - Réference: https://rspamd.com/doc/modules/clickhouse.html
  - Chartable: 
    - Description: Il regarde dans chaque mot s'il y a beaucoup de transition entre des lettres en ASCII et non ASCII.
    - Symbole de resultat: "R_MIXED_CHARSET"
    - Fichier de configuration: "local.d/chartable.conf" (pour désactiver: "enabled = false;")
    - Activation: Oui par defaut
    - Réference: https://rspamd.com/doc/modules/chartable.html  
  - DCC:
    - Description: DCC identifie via le checksum d'un message transmis à leur serveur si le message à été transmis en mass ou non.
    - Symbole de resultat: "DCC_*"
    - Fichier de configuration: "local.d/dcc.conf" 
    - Activation: Non
    - utilisation:
      - Dockerfile DCC possible: https://github.com/Neomediatech/dcc-docker/blob/master/Dockerfile
      - Utilise les ressources des serveurs DCC: https://www.dcc-servers.net/dcc/#public-servers
    - Réference: https://rspamd.com/doc/modules/dcc.html  
  - DKIM: 
    - Description: il verifie la validité de la signature DKIM d'un message.
    - Activation: Oui par defaut
    - Réference: https://rspamd.com/doc/modules/dkim.html 
  - DKIM signing: 
    - Description: Il signe les messages avec la clé DKIM selon des règles définies
    - Fichier de configuration: "local.d/dkim_signing.conf"
    - Activation: Non (vous devez avoir une clé DKIM pour l'activer; clé publique dans le DNS)
    - Réference: https://rspamd.com/doc/modules/dkim_signing.html
  - DMARC: 
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
    - utilisation: 
      - REDIS: oui pour rapport
    - Réference: https://rspamd.com/doc/modules/dmarc.html
  - Elasticsearch: 
    - Description: Permet de créer un tableau de bord sur une base "elasticsearch via kibana" afin d'analyser les statistiques générées par RSPAMD.
    - Fichier de configuration: "local.d/elastic.conf"
    - Activation: Non
    - utilisation: 
      - elasticsearch
    - Réference: https://rspamd.com/doc/modules/elastic.html
  - External Services: 
    - Description: Permet d'integrer l'analyse d'outils exterieurs (oletools, pyzor, razor, virustotal, ,...)
    - Fichier de configuration: "local.d/external_services.conf"
    - Activation: Oui pour oletools
    - utilisation: 
      - Olefy (integré au docker)
      - Possibilité de créer son module externe, exemple: https://github.com/Neomediatech/rspamd/blob/master/conf/plugins.d/pyzor.lua
    - Réference: https://rspamd.com/doc/modules/external_services.html
  - Force actions: 
    - Description: Permet de forcer une action lors du déclenchement d'un symbole.
    - Fichier de configuration: "local.d/force_actions.conf"
    - Activation: Oui
    - Réference: https://rspamd.com/doc/modules/force_actions.html
  - Fuzzy check: 
    - Description: Permet d'identifier des courriels très sembables (fuzzyhash) afin d'avoir
    - Fichier de configuration: "local.d/fuzzy_check.conf"
    - Activation: Oui
    - Réference: https://rspamd.com/doc/modules/fuzzy_check.html

#### Ecrire sa propre règle
Avec RSPAMD, il est très facil d'ecrire sa propre règle, pour plus d'information: https://rspamd.com/doc/tutorials/writing_rules.html
#### Tester vos règles
Afin de tester vos règles et surtout assurer leurs bons fonctionnements, vous pouvez utiliser l'interface graphique avec un courriel qui contient votre contenu à détecter, et verifier le déclenchement de vos règles.
#### Redis
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
#### Configuration de RSPAMD dans un autre MTA
Vous trouverez dans le lien suivant, les informations pour integrer RSPAMD dans votre MTA: https://rspamd.com/doc/integration.html .


## GTUBE <a name="gtube"></a>
### Description
Cette règle permet d'éviter que tout le monde puisse utiliser votre serveur de messagerie pour transmettre des courriels afin d'éviter les risques suivants:
  - Utilisation de ressources illégitimement;
  - Mise en liste noire de vos serveurs;
  - Usurpation d'identité.
(https://fr.wikipedia.org/wiki/Open_relay)
### Exemple de configuration
Les valeurs à verifier sont dans les variables "smtpd_recipient_restrictions", "smtpd_relay_restrictions" et "smtpd_sender_restrictions" (du fichier "/etc/postifx/main.cf"), celles-ci doivent restreindre à votre reseau "permit_mynetworks" et potentiellement à une authentifiction "permit_sasl_authenticated".
Vous trouverez plus de renseignement sur ce lien http://www.postfix.org/SMTPD_ACCESS_README.html .
### Faux positifs
Pas de faux positif connu.