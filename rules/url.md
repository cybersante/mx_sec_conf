# Règles de filtrage des URL malicieuses
Tests ACSS concernés n°:  
Date Creation: 25/09/2020  
Date dernière mise à jour: 05/10/2020  
Facilité de mise en place: Simple ~~/ Moyen / Complexe~~  

URL:
  - redirection
  - Proxy web sortant
Règles:
1. [Identifier une URL suspecte](#reject)


## Identifier une URL suspecte <a name="reject"></a>
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
  - utiliser des redirecteurs (en cascade ou non) afin de mieux cacher le site finale

### Exemple de configuration
Nous avons developpé un plugin spécifique basé sur "URL_REDIRECTOR", il est actuellement en PR sur github (https://github.com/rspamd/rspamd/pull/3507).
Voici les possibilités offertent par le plugin et les autres possibilités de RSPAMD:
  - Threat Intel
    - Utilisation des RBL sur URL (SpamHAUS, ...)
    - Utilisez une multimap avec un MISP
    - Utilisation du symbole "SEM_URIBL_FRESH15" pour identifier un domaine récemment créé
    - ...
  - Analyse statique de l'URL
    - URL avec un port spécifique: symbole 
    - URL avec une IP en direct (http://X.X.X.X/...): symbole
    - URL avec un chemin suspect (http://host/paypal.com/login.html): symbole
    - URL avec un sous domaine suspect (http://paypal.com.hacker.fr/login.html): symbole
  - Analyse dynamique de l'URL
    - URL avec une redirection
      - chaque URL extraite de redirection sera analyser (selon la profondeur configurée)
    - URL avec
### Faux positifs
