# Exemple de configuration sécurisée d'une entrée de messagerie MX
## Introduction
Ce dépot contient la configuration nécéssaire pour passer les tests de sécurité de l'outil d'analyse de la cellule ACSS/ANS présenté lors du webinaire ACSS n°4 (https://esante.gouv.fr/sites/default/files/media_entity/documents/acss_web_conference_n4.pdf - https://www.facebook.com/AgenceDuNumeriqueEnSante/videos/792330108189438/).  

Il vous permettra de trouver des exemples concrets de configuration à integrer dans votre messagerie, mais vous pouvez aussi utiliser le docker afin de directement integrer l'ensemble dans votre chaine de messagerie.

## Solution proposée
La solution proposée par la cellule ACSS utilise Rspamd (https://rspamd.com/) et clamav (https://www.clamav.net/).  
Elle sert principalement d'exemple que vous pourrez porter dans votre solution de messagerie existante, tout en prennant en compte, selon votre contexte, le risque de faux positifs que peuvent entrainer certaines règles. Il sera donc parfois nécéssaire en fonction de votre contexte d'adapter les règles.

### Limites de la solution
La sécurité informatique est complexe et cette solution permet de limiter qu'une petite partie des risques encourus par un système informatique (https://attack.mitre.org/techniques/T1566/001/ & https://attack.mitre.org/techniques/T1566/002/). 

Le plus complexe à bloquer reste les courriels avec une URL (parfois contenu dans un fichier PDF ou DOC "propre" pour complexifier l'analyse) qui permet le téléchargement d'un malware, l'utilisation d'un exploit KIT (https://fr.wikipedia.org/wiki/Exploit_(informatique)#Exploits_Web), ou d'un formulaire de phishing en ligne. Un courriel contenant ce type de lien peut avoir une apparence parfaitement légitime et peu d'éléments suspects permettant de détecter la menace. Une methode employée couramment est l'utilisation de la "Threat Intel" (https://fr.wikipedia.org/wiki/Threat_Intelligence) mais elle a ces limites (URL non connue au moment du scan, URL dans un document non parsé par le scan, URL ciblée uniquement pour vous, ...).

Ils existes des solutions proposées par des editeurs afin de réécrire ces URL pour obliger le client à passer par un "redirecteur de sécurité" qui analysera l'URL au moment de la demande par l'utilisateur. C'est une solution interessante mais qui a aussi des limites et qui au niveau de la confidentialité peut être limite si celle-ci n'est pas hebergée en interne.
