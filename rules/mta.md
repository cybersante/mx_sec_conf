# Règles de base sur le MTA 
Tests ACSS concernés n°: 1  
Date Creation: 18/09/2020  
Date dernière mise à jour: 18/09/2020  
Facilité de mise en place: Simple ~~/ Moyen / Complexe~~  

Les exemples de configuration (ci-dessous) sont basés sur postfix (http://www.postfix.org/).  

Règles:
1. [Relais de courrier ouvert](#relai)
2. [Segmentation des rôles](#segm)
3. [Haute disponibilité](#ha)
4. [Taux d'erreurs d'un client](#err)
5. [Nombre de connexions simultannées par client](#conn)
6. [Chiffrement](#cyph)
7. [Taille maximum d'un courriel](#size)
8. [Utilisateur inconnu](#user)
9. [DNS](#dns)

## Relais de courrier ouvert <a name="relai"></a>
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

## Segmentation des rôles <a name="segm"></a>
### Description
Cette règle permet une meilleure maitrise des flux entrants et sortants, et permet d'adapter au mieux les configurations de filtrages.
(https://fr.wikipedia.org/wiki/Open_relay)
### Exemple de configuration
La segmentation à privilégier au niveau de l'architecture:
  - MX n'est qu'un serveur de reception (en aucun cas il sera émeteur), il est placé en DMZ/DMZ-IN (son port [25/TCP] est accessible depuis internet)
  - SMTP-OUT sortant vers internet, il est placé en DMZ/DMZ-OUT (son port n'est pas accessible depuis internet).
  - SMTP pour nomade avec authentification, il est placé en DMZ/DMZ-IN (son port est accessible depuis internet), de préférence, il transmettra les courriels vers SMTP-OUT (afin que les courriels soient analysés).
    - permettra de forcer l'utilisation du TLS ("smtpd_enforce_tls = yes" && "smtpd_tls_auth_only = yes")
### Faux positifs
Pas de faux positif connu.

## Haute disponibilité <a name="ha"></a>
### Description
Cette règle permet d'éviter de perdre des courriels en cas d'attaque par DDoS/DoS ou d'un crash involontaire d'un des serveurs MX.
### Exemple de configuration
Les éléments importants de la haute disponibilité:
  - Vous devez avoir plusieurs serveurs MX (sur des connexions différentes)
  - Vous devez avoir une file de rétention suffisante pouvant supporter l'indisponibilité d'un serveur interne (ex: MDA) durant la periode "HNO" (un weekend par exemple);
    - sous entend supervision de vos services (mta, mda, ...);
### Faux positifs
Pas de faux positif connu.

## Taux d'erreurs d'un client <a name="err"></a>
### Description
Cette règle permet de reduire les clients qui vous transmettent des nombreux courriels avec un taux d'erreurs importants (ex. erreur: utilisateur inconnu).
### Exemple de configuration
Les valeurs à verifier sont dans les variables "smtpd_recipient_restrictions", "smtpd_relay_restrictions" et "smtpd_sender_restrictions" (du fichier "/etc/postifx/main.cf"), celles-ci doivent restreindre à votre reseau "permit_mynetworks" et potentiellement à une authentifiction "permit_sasl_authenticated".
Vous trouverez plus de renseignement sur ce lien http://www.postfix.org/TUNING_README.html#slowdown .
### Faux positifs
Pas de faux positif connu (le client n'est que ralenti).

## Nombre de connexions simultannées par client <a name="conn"></a>
### Description
Cette règle permet de reduire les clients qui vous transmettent des nombreux courriels avec un taux d'erreurs importants (ex. erreur: utilisateur inconnu).
### Exemple de configuration
La valeur à verifier est dans la variable "smtpd_client_connection_count_limit" (du fichier "/etc/postifx/main.cf").
Vous trouverez plus de renseignement sur ce lien http://www.postfix.org/TUNING_README.html#conn_limit .
### Faux positifs
Pas de faux positif connu.

## Chiffrement <a name="cyph"></a>
### Description
Cette règle permet de garantir la confidentialité d'un échange afin d'éviter le risque lié a l'écoute du réseau.
Privilégiez l'échange par chiffrement sur l'ensemble de votre réseau, lors de la réception et de l'envoi de courriel.
### Exemple de configuration
Vous pouvez utiliser "let's encrypt" (https://letsencrypt.org/fr/) pour generer vos certificats.
Mettez le certificat (clé publique et clé privée) dans les variables "smtpd_tls_cert_file" et "smtpd_tls_key_file" (du fichier "/etc/postifx/main.cf").
Activer le TLS (http://www.postfix.org/postconf.5.html#smtp_tls_security_level) selon le profile désiré ("MAY" à minima).
### Faux positifs
Pas de faux positif connu.

## Taille maximum d'un courriel <a name="size"></a>
### Description
Cette règle permet de limiter la taille d'un courriel entrant afin d'éviter les risques suivants:
  - Le deni de service par l'épuisement des ressources (l'espace disque majoritairement);
  - Le contournement des protections qui sont souvent limitées dans la taille maximum de traitement.
### Exemple de configuration
Notre exemple est basé sur postfix (http://www.postfix.org/postconf.5.html).  
La valeur à verifier est dans la variable "message_size_limit" (du fichier "/etc/postifx/main.cf"), celle-ci doit être à "10240000" (soit 10MO).  
Cette valeur est conseillée, mais selon votre contexte vous pouvez la reduire (risque de rejet de courriel légitime) ou l'augmenter (risque de DoS ou dépassement des seuils de protection).
### Faux positifs
Vous pourriez avoir des faux positifs si des utilisateurs exterieurs vous transmette des pieces jointes légitimes dépassant ce seuil.  
Il est donc important de rejeter le message avec l'élément d'information indiqant que le courriel est trop important, ce qui permettra à l'expéditeur de savoir que la personne n'a pas reçu le courriel.  
L'interne ne devrait pas être touché par cette restriction que l'on applique sur le "MX" (entrée de courriel exterieur).  

## Utilisateur inconnu <a name="user"></a>
### Description
Cette règle permet d'éviter la recherche par un attaquant d'adresses courriels valides.
### Exemple de configuration
Deux possibilités:
  - Le MX ne connait pas les boites existantes et non existante, c'est donc le SMTP-OUT qui transmettra l'information que l'utilisateur n'existe pas (à éviter);
  - Le MX a la table des utilisateurs existant et rejette directement le client lors de l'échange si l'adresse courriel n'existe pas (permet le controle des boites "internes" et "extrernes").
    - Changer le code de rejet qui indique que la boite n'existe pas (code: 450) avec la variable "unverified_recipient_reject_code";
    - Limiter les informations données à l'utilisateur avec la variable "unverified_recipient_reject_reason";
    - Configurer le ralentissement sur taux d'erreurs afin qu'il soit limité dans ces recherches;
### Faux positifs
Le risque est qu'un expediteur légitime se trompe dans l'adresse courriel mais ne soit jamais prévenu de son erreur.

## DNS <a name="dns"></a>
### Description
Cette règle permet de garantir une bonne stabilité de votre messagerie en cas d'indisponibilité de votre DNS interne mais aussi de proteger votre SI interne.
Postfix et les éléments de protection génèrent un nombre important de requetes DNS.
### Exemple de configuration
Utilisez des serveurs DNS spécifiques à la messagerie.
### Faux positifs
Pas de faux positif connu.

