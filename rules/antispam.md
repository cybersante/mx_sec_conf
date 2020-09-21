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
  
### Configuration dans le MTA
Comme l'indique Monsieur G. CATTEAU dans son retour d'experience, il est préférable dans un premier temps de mettre RSPAMD en "no action" pour prendre le temps d'identifier les risques de faux positif pouvant engendrer de la perte de courriels légitimes (https://rspamd.com/doc/workers/rspamd_proxy.html#mirroring).
#### Postfix
Vous trouverez dans le lien suivant, les informations pour integrer RSPAMD dans postfix via le protocol milter: https://rspamd.com/doc/workers/rspamd_proxy.html .  
Pensez à tester sans action dans un premier temps (https://rspamd.com/doc/workers/rspamd_proxy.html#mirroring).  
Si vous utilisez notre docker-compose, alors vous pouvez integrer à postfix dans "/etc/postfix/main.cf":
  - si votre docker est sur le meme serveur que postfix: "smtpd_milters = inet:172.17.0.1:9900"
  - si votre docker est sur un autre serveur que postfix: "smtpd_milters = inet:IP-DOCKER:9900" 
    - (pensez à filter le port avec netfilter qu'il ne soit accessible qu'aux IP MX/SMTP)
    - modifier docker-compose.yml en replacant "172.17.0.1:9900:9900" par "9900:9900"
#### Autres
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
