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
La technique de l'URL malicieuse est très efficace car l'attaquant sait que si son adresse n'est pas ne liste noire, alors il y a des grandes chances qu'elle passe vos protections.  
Si il utilise une URL en "https" votre proxy (ou IDS/IPS) ne verra rien de la transaction (sauf proxy qui casse le chiffrement).  

L'attaquant a plusieurs possibilités, qui peut mixer selon les cas afin d'ouvrir un site malicieux, chaque methode ouvre des possibilités de détection:
  - utiliser un site web qu'il a piraté (avec le domaine du site piraté)
  - utiliser un serveur qu'il a piraté (soit avec l'host du serveur ou en utilisant un domaine qu'il a créé)
  - utiliser un site qu'il heberge avec son propre domaine (peu rentable car il sera rapidement en liste noire)
  - utiliser un site qu'il a créer sur un hebergeur en ligne gratuit ou en promo (2 mois gratuit => il en a besoin que de quelques jours).
    - avec son propre nom de domaine
    - avec un sous domaine de l'hebergeur
  - utiliser un service en ligne qui permet de créer du contenu dynamique (google docs, ...)
  - utiliser des redirecteurs (en cascade ou non) afin de mieux cacher le site finale


### Exemple de configuration
### Faux positifs
