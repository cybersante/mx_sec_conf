# Règles de filtrage des URL malicieuses
Tests ACSS concernés n°:  
Date Creation: 25/09/2020  
Date dernière mise à jour: 25/09/2020  
Facilité de mise en place: Simple ~~/ Moyen / Complexe~~  

URL:
  - redirection
  - 
Règles:
1. [Identifier une URL suspecte](#reject)


## Identifier une URL suspecte <a name="reject"></a>
### Description
La technique de l'URL malicieuse est très efficace car l'attaquant sait que si son adresse n'est pas en liste noire, alors il y a des grandes chances qu'elle passe vos protections.  
Si il utilise une URL en "https" votre proxy (ou IDS/IPS) ne verra rien de la transaction (sauf si votre proxy casse le chiffrement).  

L'attaquant a plusieurs possibilités, qui peut mixer selon les cas afin d'ouvrir un site malicieux, chaque methode ouvre des possibilités de détection:
  - utiliser un site web qu'il a piraté (avec le domaine du site piraté)
    - Threat Intel: liste noire (spamhaus), ...
    - Chemin et/ou arguments spécifiques
    - Extension suspecte en direct
    - Statistiques internes sur le domaine
  - utiliser un serveur qu'il a piraté (soit avec l'host du serveur ou en utilisant un domaine qu'il a créé)
    - Threat Intel
    - Chemin et/ou arguments spécifiques
    - Extension suspecte en direct
    - Statistiques internes sur le domaine
    - Port spécifique
    - Certificat non valide
    - Certificat très récent
    - vhost connu
    - 
  - utiliser un site qu'il heberge avec son propre domaine (peu rentable car il sera rapidement en liste noire)
    - Threat Intel
    - Domaine avec creation très récente (SEM_URIBL_FRESH15)
    - Certificat TLS avec creation très récente (si https)
    - Pas de MX (souvent)
  - utiliser un site qu'il a créer sur un hebergeur en ligne gratuit ou en promo (2 mois gratuit => il en a besoin que de quelques jours).
    - avec son propre nom de domaine
      - Threat Intel
      - Domaine avec creation très récente (SEM_URIBL_FRESH15) (Service API prochainement)
      - Protection des informations de registre
      - Adresse Email de registration
      - Certificat TLS avec creation très récente (si https)
      - Pas de MX (souvent)
    - avec un sous domaine de l'hebergeur
      - si https -> Certificat TLS avec creation très récente (Service API) sauf *.domain
      - ...
  - utiliser un service en ligne qui permet de créer du contenu dynamique (google docs, ...)
  - utiliser des redirecteurs (en cascade ou non) afin de mieux cacher le site finale


### Exemple de configuration
Voici comment détecter les éléments suivants avec RSPAMD:
  - Threat Intel
    - Utilisation des RBL
  - Chemin et/ou arguments spécifiques
    - Creation d'une regexp sur "url"
  - Extension suspecte en direct
    - Statistiques internes sur le domaine
    - Port spécifique
    - Certificat non valide
    - Certificat très récent
    - vhost connu
### Faux positifs
