# Règles de protection des services de la messagerie exposés sur internet
Tests ACSS concernés n°: aucun  
Date Creation: 25/09/2020  
Date dernière mise à jour: 25/09/2020  
Facilité de mise en place: Simple ~~/ Moyen / Complexe~~  

Règles:
1. [Proteger vos services avec authentification](#auth)
2. [limiter votre SMTP sortant accessible de l'exterieur](#limit)

## Proteger vos services avec authentification <a name="auth"></a>
### Description
Il est possible d'exposer des services de messagerie sur internet comme: IMAP(S)/POP(S) ou SMTP(S) sortant pour les utilisateurs nomades.  
Ces services sont susceptible d'être attaqué par brute force, faire l'objet de rejeu de mot de passe issue d'une fuite ou de phishing.  
Si vous avez un webmail demandez vous si ces services sont réellement nécéssaires... Car si vous avez mis en place la double authentification sur webmail alors votre service IMAP/POP/SMTPS represente une possibilité de contournement pour un attaquant.  

### Exemple de configuration
A notre connaissance, il n'est pas possible de mettre de la double authentification sur un service comme IMAP/POP/SMTPS.  
Si vous souhaitez vraiment mettre à disposition ces services sur internet pour vos utilisateurs, vous pouvez utiliser l'authentification par certificat (pas de brute force, ni de rejeu de mot de passe possible, et de phishing possible). Seule solution, compromettre le poste et voler le certificat.  
Exemple: https://blog.mortis.eu/blog/2017/06/dovecot-and-postfix-with-client-cert-auth.html  

Si vous n'utilisez pas le choix ci-dessus alors vous pouvez toujours utiliser fail2ban ainsi que des listes noires/GEOIP d'IP pour filtrer les connexions aux services.

Pour finir, activer (ou forcer => STARTLS) le chiffrement (IMAPS au lieu de IMAP; POP3S au lieu de POP3; SMTPS au lieu de SMTP).
### Faux positifs
Si vous utilisez la GEOIP, alors un travailleur à l'étranger pourrait être bloqué.

## limiter votre SMTP sortant accessible de l'exterieur <a name="limit"></a>
### Description
Cette règle permet de limiter l'impact si un compte avec SMTPS est compromis.
Il est important que la politique de sortie des courriels vers internet (en provenance du smtps internet) soient plus stricte que l'interne.

### Exemple de configuration
Il faut faire passer le flux de sortie (du smtp internet vers internet) par une instance RSPAMD/CLAMAV spécifique (de préférence), et effectuer les filtrages comme si c'etait de la reception:
  - interdire l'usurpation d'identité en sortie;
  - interdire les pièces jointes dangereuses;
  - interdire les reply-to hors domaine;
  - interdire les symboles "XOIP_SUSPECT" (si vous avez activé l'ajout de l'information "X-Originating-IP");
  - interdire les URL suspectes.
  
De plus, il faut limiter le nombre d'envoi d'un utilisateur à la minute (généralement, l'attaquant utilise un script qui va générer un flux très important sur un laps de temps court).  
Vous pouvez utiliser le module rate_limit de RSPAMD pour réaliser cette action (https://rspamd.com/doc/modules/ratelimit.html).
### Faux positifs
Pas de faux positif connu.
