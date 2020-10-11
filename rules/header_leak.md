# Règles de limitation des fuites d'informations sur l'architecture interne
Tests ACSS concernés n°: aucun mais informations présentes dans le rapport  
Date Creation: 25/09/2020  
Date dernière mise à jour: 25/09/2020  
Facilité de mise en place: Simple ~~/ Moyen / Complexe~~  

Règles:
1. [Limiter la fuite d'informations dans les en-têtes](#header)
2. [Limiter la fuite d'informations dans les "banner" de connexion de vos services externes](#banner)

## Limiter la fuite d'informations dans les en-têtes <a name="header"></a>
### Description
Si vous regardez les en-têtes d'un courriel, vous trouverez beaucoup d'informations sur le système informatique de l'expéditeur (service, ip interne, application, version des applications, client de messagerie, ...).  
Afin de limiter ces informations, il faut nettoyer les en-têtes en sortie.
### Exemple de configuration
RSPAMD permet de nettoyer vos entêtes avec le module: https://rspamd.com/doc/modules/milter_headers.html#remove-headers-163  
Vous pouvez aussi utiliser postfix: https://askubuntu.com/questions/78163/when-sending-email-with-postfix-how-can-i-hide-the-sender-s-ip-and-username-in/78168#78168

### Faux positifs
Aucun

## Limiter la fuite d'informations dans les "banner" de connexion de vos services externes <a name="banner"></a>
### Description
Identifier l'ensemble des ports que vous exposez sur internet pour vos services de messagerie, connectez vous dessus (avec telnet, netcat, ou putty), et identifier les "banner" trop verbeuses.  
Vous pouvez laisser l'information sur l'application, par exemple postfix, mais il n'est pas nécessaire d'indiquer la version et donc de donner l'oportunité à un attaquant de vous cibler immediatement si votre version a une faille.  
### Exemple de configuration
Exemple pour postfix utiliser la variable "smtpd_banner" dans "main.cf".

### Faux positifs
Aucun
