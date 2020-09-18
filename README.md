# Securiser l'entrée de messagerie (MX)
## Introduction
Ce dépot contient la configuration nécéssaire pour passer les tests de sécurité de l'outil d'analyse de la cellule ACSS/ANS présenté lors du webinaire ACSS n°4 (https://esante.gouv.fr/sites/default/files/media_entity/documents/acss_web_conference_n4.pdf - https://www.facebook.com/AgenceDuNumeriqueEnSante/videos/792330108189438/).  

Au delà de la couverture des tests proposés par le service ACSS, il intègre les principaux risques liés à la messagerie professionnelle (à l'exception des spams classiques qui sont souvent soumis à l'apprentissage):
  - DDoS et DoS (https://fr.wikipedia.org/wiki/Attaque_par_d%C3%A9ni_de_service);
  - Phishing:
    - Campagne de malware par courriel avec pièce jointe;
    - Campagne de pishing par courriel avec URL (dans un fichier ou dans le corp du message) vers formulaire en ligne;
    - Campagne de pishing par courriel avec reponse par courriel vers un adresse controlée par l'attaquant (Reply-to);
  - Malware:
    - Campagne de malware par courriel avec pièce jointe;
    - Campagne de malware par courriel avec URL (dans un fichier ou dans le corp du message) vers un site avec un contenu malicieux (Exploit Kit, Fake Virus, Tech Scam, Malware);
  - Utilisation de methodes d'obfuscation pour contourner les protections de messagerie afin de realiser une des attaques ci-dessus;
  - Usurpation d'identité afin de realiser une des attaques ci-dessus plus facilement ou d'obtenir des informations (ex: Arnaque au président);
  - Brute force des services de la messagerie exposés sur internet (webmail, imap, ...);
  - Fuite d'identifiants de messagerie avec risque de compromission d'un compte;
  - Utilisation de votre messagerie pour transmettre des courriels malicieux;
  
Il vous permettra de trouver des exemples concrets de configuration à integrer dans votre messagerie, mais vous pouvez aussi utiliser le docker afin de directement integrer l'ensemble dans votre chaine de messagerie.

## Solution proposée
La solution proposée par la cellule ACSS utilise Rspamd (https://rspamd.com/) et clamav (https://www.clamav.net/).  
Elle sert principalement d'exemple que vous pourrez porter dans votre solution de messagerie existante, tout en prennant en compte, selon votre contexte, le risque de faux positifs que peuvent entrainer certaines règles. Il sera donc parfois nécéssaire en fonction de votre contexte d'adapter les règles.

### Limites de la solution
La sécurité informatique est complexe et cette solution permet de limiter qu'une petite partie des risques encourus par un système informatique (https://attack.mitre.org/techniques/T1566/001/ & https://attack.mitre.org/techniques/T1566/002/). 

Le plus complexe à bloquer reste les courriels avec une URL (parfois contenu dans un fichier PDF ou DOC "propre" pour complexifier l'analyse) qui permet le téléchargement d'un malware, l'utilisation d'un exploit KIT (https://fr.wikipedia.org/wiki/Exploit_(informatique)#Exploits_Web), ou d'un formulaire de phishing en ligne. Un courriel contenant ce type de lien peut avoir une apparence parfaitement légitime et peu d'éléments suspects permettant de détecter la menace. Une methode employée couramment est l'utilisation de la "Threat Intel" (https://fr.wikipedia.org/wiki/Threat_Intelligence) mais elle a ces limites (URL non connue au moment du scan, URL dans un document non parsé par le scan, URL ciblée uniquement pour vous, ...).

Il existe des solutions proposées par des editeurs afin de réécrire ces URL pour obliger le client à passer par un "redirecteur de sécurité" qui analysera l'URL au moment de la demande par l'utilisateur. C'est une solution interessante mais qui a aussi des limites et qui au niveau de la confidentialité peut être limite si celle-ci n'est pas hebergée en interne.

Pour finir, il est important de ne pas tout miser sur les protections peripheriques, en particulier dans le cadre des ordinateurs nomades (ex: télétravail), qui peuvent ne plus recevoir correctement les mises à jour vitales (AV, WSUS, ...) et qui sont souvent en direct sur internet.

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
