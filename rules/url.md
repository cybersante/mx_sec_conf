# Règles de filtrage des URL malicieuses
Tests ACSS concernés n°: 71, 72, 75  
Date Creation: 25/09/2020  
Date dernière mise à jour: 05/10/2020  
Facilité de mise en place: Simple ~~/ Moyen / Complexe~~  

Règles:
1. [Identifier une URL suspecte](#suspect)
2. [Proxy web sortant](#proxy)

## Identifier une URL suspecte <a name="suspect"></a>
### Description
La technique de l'URL malicieuse est très efficace car l'attaquant sait que si son adresse n'est pas en liste noire, alors il y a des grandes chances qu'elle passe vos protections.  
Si il utilise une URL en "https" votre proxy (ou IDS/IPS) ne verra rien de la transaction (sauf si votre proxy casse le chiffrement).  

L'attaquant a plusieurs possibilités, qu'il peut mixer selon les cas afin d'ouvrir un site malicieux:
  - utiliser un site web qu'il a piraté (avec le domaine du site piraté)
  - utiliser un serveur qu'il a piraté (soit avec l'host du serveur ou en utilisant un domaine qu'il a créé)
  - utiliser un site qu'il heberge avec son propre domaine (peu rentable car il sera rapidement en liste noire)
  - utiliser un site qu'il a créer sur un hebergeur en ligne gratuit ou en promo (2 mois gratuit => il en a besoin que de quelques jours).
    - avec son propre nom de domaine
    - avec un sous domaine de l'hebergeur
  - utiliser un service en ligne qui permet de créer du contenu dynamique (google docs, ...)
  - utiliser des redirecteurs (en cascade ou non) afin de mieux cacher le site final

### Exemple de configuration
Nous avons developpé un plugin spécifique basé sur "URL_REDIRECTOR", il est actuellement en PR sur github (https://github.com/rspamd/rspamd/pull/3508).  
Ce module nécéssite de revoir la valeur par défaut de l'option globale 'task_timeout' afin de laisser le temps au plugin de faire l'analyse sans être coupé.  
Voici les possibilités offertent par le plugin et les autres possibilités de RSPAMD:
  - Threat Intel
    - Utilisation des RBL sur URL (SpamHAUS, ...)
    - Utilisez une multimap avec un MISP
    - Utilisation du symbole "SEM_URIBL_FRESH15" pour identifier un domaine récemment créé
    - ...
  - Analyses statiques de l'URL
    - URL avec un port spécifique: symbole "URL_WITH_NO_STANDARD_PORT"
    - URL avec une IP en direct (http://X.X.X.X/...): symbole "URL_WITH_IP"
    - URL avec un chemin suspect (http://host/paypal.com/login.html): symbole "URL_SUSPECT_PATH"
    - URL avec un sous domaine suspect (http://paypal.com.hacker.fr/login.html): symbole "URL_WITH_SUSPECT_SUBHOST"
    - URL avec un nombre de partie de sous domaine trop important (bla.bla.bla.bla.domain.fr): symbole "SUBHOST_HAS_LOTOF_PART"
    - URL qui utilise une hebergeur gratuit: "URL_USE_FREEHOST"
    - URL qui utilise une site de téléchargement gratuit: "URL_DOWNLOAD_ON_FREESITE"
    - URL
  - Analyses dynamiques de l'URL
    - URL avec une resolution IP contenue dans la liste noire: symbole "URL_RESOLV_IP_IN_BLACKLIST"
    - URL avec un domaine qui n'a pas d'enregistrement MX: symbole "URL_WITH_DOMAIN_NO_MX
    - URL avec le hostname et le domaine qui ont la même resolution DNS: symbole "URL_WITH_HOST_RESOLV_DOMAIN"
    - URL avec une redirection: symbole "URL_REDIRECT"
      - chaque URL extraite de redirection sera analyser (selon la profondeur configurée)
      - URL qui dépasse le seuil de redirection: symbole "URL_TOO_MUCH_REDIRECT"
    - URL avec un mimetype suspect: symbole "URL_SUSPECT_MIMETYPE"
    - URL avec téléchargement: symbole "URL_DOWNLOAD"
    - URL avec téléchargement d'un fichier à risque: symbole "URL_SUSPECT_FILENAME"

Vous pouvez configurer le plugin selon les options indiquées dans la PR: https://github.com/rspamd/rspamd/pull/3508 afin d'adapter à votre contexte ou en cas de faux positifs.  
De plus, vous pouvez adapter le score de chacun de ces symboles.  

### Faux positifs
Vous pouvez configurer le plugin selon les options indiquées dans la PR: https://github.com/rspamd/rspamd/pull/3508 afin d'adapter en cas de faux positif.

## Proxy web sortant <a name="proxy"></a>
### Description
Il est possible de contourner la protection de messagerie, ou bien meme si votre utilisateur utilise une autre messagerie (personnelle).  
Il est donc important d'avoir un proxy web sortant avec une filtration adapter.
L'objectif de la protection du proxy est de limiter:
  - le téléchargement de charge depuis le poste client à l'insu de la victime;
  - la communication entre le poste/serveur infecté et le BOTNET/C&C;

Certains malwares n'ont pas de fonctionnalité pour utiliser un proxy web sortant, ce qui va donc souvent les paraliser. 

Voici ce que vous pouvez limiter sur le proxy:
  - Connexion directe vers une IP sans resolution (ex: http://X.X.X.X);
  - Connexion vers un port non standard;
  - L'utilisation de tunnel (verifier qu'il s'agit bien d'une connexion TLS lors de connexion "https" - https://wiki.squid-cache.org/Features/SslPeekAndSplice)
  - L'utilisation de listes noires (Threat Intel) et categories (si votre proxy le permet)
  - L'utilisation de modules ICAP
    - http://www.squid-cache.org/Misc/icap.html
    - https://docs.diladele.com/administrator_guide_stable/index.html
    - Vous pouvez utiliser l'ICAP pour afficher un message d'avertissement lorsque vous détectez afin de verifier s'il s'agit bien d'une demande "humaine" (cela permettra de facilement casser les communucations vers un botnet/C&C qui ne sera pas contourner automatiquement l'advertissement):
       - hostname jamais vu sur votre réseau
       - useragent jamais vu pour l'utilisateur "X"
       - ...

Pensez à activer les logs de votre proxy avec une bonne rétention et mais aussi les informations nécéssaires à une investigation (referer, user-agent, ...).
  
### Exemple de configuration
Prochainement, nous proposerons une configuration pour le proxy squid. 

### Faux positifs

