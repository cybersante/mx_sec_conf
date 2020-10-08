# Securiser la réception des messages (MX)
## Introduction
Ce dépot contient les configurations de sécurité permettant de passer les tests de l'outil d'analyse des vulnérabilités de la cellule ACSS(ANS) présenté lors du webinaire ACSS n°4 (https://esante.gouv.fr/sites/default/files/media_entity/documents/acss_web_conference_n4.pdf - https://www.facebook.com/AgenceDuNumeriqueEnSante/videos/792330108189438/).  

Au delà de la couverture des tests mis en oeuvre par le service, il couvre aussi les principaux risques suivants liés à la messagerie professionnelle (à l'exception des spams classiques qui sont souvent soumis à l'apprentissage):
  - DDoS et DoS (https://fr.wikipedia.org/wiki/Attaque_par_d%C3%A9ni_de_service) ;
  - Phishing:
    - Campagne de malware par courriel avec pièce jointe ;
    - Campagne de phishing par courriel avec une URL (dans un fichier ou dans le corps du message) vers un formulaire en ligne ;
    - Campagne de phishing par courriel avec une reponse par courriel vers une adresse controlée par l'attaquant (Reply-to) ;
  - Malware:
    - Campagne de malware par courriel avec pièce jointe ;
    - Campagne de malware par courriel avec URL (dans un fichier ou dans le corp du message) vers un site avec un contenu malveillant (Exploit Kit, Fake Virus, Tech Scam, Malware) ;
  - Utilisation de methodes d'obfuscation de code pour contourner les protections de messagerie afin de realiser une des attaques présentées ci-dessus ;
  - Usurpation d'identité afin de realiser une des attaques ci-dessus plus facilement ou d'obtenir des informations (ex: Arnaque au président) ;
  - Brute force des services de la messagerie exposés sur internet (webmail, imap, ...) ;
  - Fuite d'identifiants de messagerie avec risque de compromission d'un compte ;
  - Utilisation de votre messagerie pour transmettre des courriels malveillants ;
  
Ce dépôt contient des exemples concrets de configuration à integrer dans votre système de messagerie, mais l'utilisation de docker permet d'intégrer directement l'ensemble des contrôles dans votre chaine de messagerie.

## Solution proposée
La solution proposée par la cellule ACSS utilise Rspamd (https://rspamd.com/) et clamav (https://www.clamav.net/).  
Les règles présentées peuvent être réutilisées dans votre solution de messagerie existante, tout en prenant en compte, selon votre contexte, le risque de faux positifs que peuvent entrainer certaines règles. Il est donc parfois nécessaire de les adapter.

### Limites de la solution
La protection d'un système numérique (ou système d'information) nécessite la mise en place de nombreuses mesures de sécurité organisationnelles et techniques. Cette solution permet de couvrir qu'une petite partie des risques encourus par le système (https://attack.mitre.org/techniques/T1566/001/ & https://attack.mitre.org/techniques/T1566/002/). 

Les courriels avec une URL (parfois contenu dans un fichier PDF ou DOC "propre" pour complexifier l'analyse) permettant le téléchargement d'un malware, l'utilisation d'un exploit KIT (https://fr.wikipedia.org/wiki/Exploit_(informatique)#Exploits_Web) ou d'un formulaire de phishing en ligne sont les plus complexes à détecter et à bloquer. Un courriel contenant ce type de lien peut avoir une apparence parfaitement légitime et peu d'éléments suspects permettant de détecter la menace. Une methode employée couramment est la "Threat Intel" (https://fr.wikipedia.org/wiki/Threat_Intelligence) mais elle a ses limites (URL non connue au moment du scan, URL dans un document non parsé par le scan, URL ciblée uniquement pour vous, ...).

Il existe des solutions proposées par des editeurs qui contraignent le client de messagerie à passer par un "redirecteur de sécurité" qui analyse l'URL (ex: proofpoint analyse sur liste noire sans connexion ; office365 connexion methode 'HEAD') afin de le réécrire au moment de la demande d'accès par l'utilisateur. C'est une solution intéressante mais qui a aussi des limites, de plus si la solution n'est pas gérée en interne, les URL sont transmises à un tiers.

Pour finir, il est important de ne pas tout miser sur les protections péripheriques, en particulier dans le cadre de l'utilisation d'ordinateurs nomades (ex: télétravail). En effet, ces machines peuvent se trouver dans un contexte où elles ne sont plus en mesure de recevoir correctement les mises à jour vitales (AV, WSUS, ...) et où elles sont en accès direct sur internet.

### Les règles
  - [Base MTA](rules/mta.md)
  - [Mise en place antispam](rules/antispam.md)
  - [Mise en place antivirus](rules/antivirus.md)
  - [Protection de l'identité](rules/ident.md)
  - [Filtrage des pièces jointes malicieuses](rules/attachment.md)
  - [Filtrage des URL malicieuses](rules/url.md)
  - [Filtrage des Reply-To](rules/reply.md)
  - [Filtrage des anomalies](rules/anomalies.md)
  - [Protection de son webmail](rules/webmail.md)
  - [Protection des services de la messagerie exposés sur internet](rules/internet.md)
  - [Limitation des fuites d'informations sur l'architecture interne](rules/header_leak.md)
