# Règles de protection de son webmail
Tests ACSS concernés n°: aucun  
Date Creation: 25/09/2020  
Date dernière mise à jour: 25/09/2020  
Facilité de mise en place: Simple ~~/ Moyen / Complexe~~  

Règles:
1. [L'authentification](#auth)
2. [Limitation des comptes webmail](#limit)

## L'authentification sur webmail <a name="auth"></a>
### Description
Parce que l'on ne peut jamais garantir à 100% qu'une attaquant n'arrivera pas à obtenir les identifiants d'un de vos utilisateurs (phishing, brute force, rejeu de mot de passe, ...), il est important d'avoir une authentification forte et de surveiller vos logs.  
### Exemple de configuration
La majorité des webmails (commerciaux ou open source) permettent l'utilisation de la double authentification qui reste un de meilleurs moyens pour eviter le drame!  
Si malheureusement, vous ne souhaitez pas reccourrir à ce mecanisme, voici les mesures que vous pouvez mettre en place:
  - Filtrage GEOIP & liste noire avec surveillance (pourrait indiquer un compte compromis)
  - Empreinte du poste utilisateur ("IP Country/IP provider/User-Agent") et alerte en cas de nouvelle empreinte
  - Mecanisme anti-brute force (exemple: fail2ban)
### Faux positifs
Si vous utilisez la GEOIP, alors un travailleur à l'étranger pourrait être bloqué.

## Limitation des comptes webmail <a name="limit"></a>
### Description
Cette règle permet de limiter l'impact si un compte webmail est compromis.
Il est important que la politique de sortie des courriels vers internet (en provenance du webmail) soient plus stricte que l'interne.

### Exemple de configuration
Il faut faire passer le flux de sortie (du webmail vers internet) par une instance RSPAMD/CLAMAV spécifique (de préférence), et effectuer les filtrages comme si c'etait de la reception:
  - interdire l'usurpation d'identité en sortie;
  - interdire les pieces jointes dangereuses;
  - interdire les reply-to hors domaine;
  - interdire les symboles "XOIP_SUSPECT" (si vous avez activé l'ajout de l'information "X-Originating-IP");
  - interdire les URL suspectes.
  
De plus, il faut limiter le nombre d'envoi d'un utilisateur à la minute (généralement, l'attaquant utilise un script qui va générer un flux très important sur un laps de temps court).  
Vous pouvez utiliser le module rate_limit de RSPAMD pour realiser cette action (https://rspamd.com/doc/modules/ratelimit.html).
### Faux positifs
Pas de faux positif connu.
