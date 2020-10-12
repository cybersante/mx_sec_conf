# Règles de protection contre les anomalies
Tests ACSS concernés n°:   
Date Creation: 25/09/2020  
Date dernière mise à jour: 25/09/2020  
Facilité de mise en place: Simple ~~/ Moyen / Complexe~~  

Pour rappel, les anomalies volontairement intégrées dans un courriel sont utilisées principalement pour coutourner des protections.  
Les objectifs de l'attaquant sont:
 - de contourner l'antivirus et le filtre sur les fichiers (exemples: interdiction d'un exécutable);
 - de contourner les protections de filtrage d'URL malveillante ou de réécriture d'URL;
 - d'exploiter une anomalie qui va alterer l'affichage des informations sur le courriels pour induire en erreur l'utilisateur;
 - d'exploiter une faille dans le serveur ou le client de messagerie;
   - Il est important de suivre les mises à jour de tous les éléments qui rentrent en interaction avec les composants de la messagerie. Par exemple, si une librairie xml ou zip avait une CVE, il est possible que vos outils de protection l'utilisent pour analyser ce types de fichier (zip ou xml) et donc pourrait les rendre vulnerables.   

Règles:
1. [Protéger vous des anomalies pour faire passer une pièce jointe malveillante](#atta)
2. [Protéger vous des anomalies pour faire passer une URL malveillante](#url)
3. [Protéger vous des anomalies qui vont induire en erreur l'utilisateur](#reply)
4. [Protéger vous des anomalies qui pourrait exploiter une faille logiciel](#cve)
## Protéger vous des anomalies pour faire passer une piece jointe malicieuse <a name="atta"></a>
### Description
Si l'attaquant veut contourner vos protections de messagerie pour vous transmettre une pièce jointe, il va chercher à mettre une "anomalie" dans la structure du message, utiliser plusieurs encodages successivement, ou utiliser des caractères speciaux.  
Certaines applications vont la "réparer" et pourront la lire sans aucun problème alors que d'autres ne verront que des données incompréhensibles.  
Généralement, votre client lourd de messagerie ou le webmail va plutot être du coté des applications sachant "réparer", alors que l'outil de protection lui sera parfois dans l'incompréhension.  
Il est donc important de connaitre les limites de vos outils de protection (qu'il soit commercial ou non): https://nvd.nist.gov/vuln/detail/CVE-2019-19680, https://kc.mcafee.com/corporate/index?page=content&id=SB10161, ...  

### Exemple de configuration
RSPAMD gère très bien les anomalies dans les en-têtes mais il a plus de mal dans la structure du message (comme beaucoup de solutions).  
Par contre, clamav semble bien mieux gérer ces anomalies et comme RSPAMD est configuré pour transmettre tout le courriel à l'antivirus, il devrait pouvoir détecter une pièce jointe malveillante à partir des [règles yara](rules/attachment.md).

### Faux positifs
Oui sur les règles yara (voir les indications dans la fiche [Règles de protection contre les pièces jointes malicieuses](rules/attachment.md).

## Protéger vous des anomalies pour faire passer une URL malicieuse <a name="url"></a>
### Description
L'attaquant qui veut transmettre un courriel avec une URL malicieuse doit coutourner l'analyse et parfois la réécriture d'url (comme la technologie de chez proofpoint par exemple).  
Il va privilégier un lien cliquable, donc du code HTML ou un document type doc/pdf. 
Il existe plusieurs méthodes pour essayer de faire cela, par exemple:
  - utiliser plusieurs encodages successivement;
  - utiliser des caractères spéciaux;
  - casser la structure html d'un message;
La encore, certaines applications vont la "réparer" et pourront la lire sans aucun problème alors que d'autres ne verront que des données incompréhensibles.  
L'objectif est bien que la protection ne soit pas en mesure de voir qu'il y a une URL et donc d'appliquer les contrôles prévus.  

### Exemple de configuration
RSPAMD saura gérer la problématique des encodages et caractères spéciaux car son moteur est conçu pour corriger ces anomalies avant les autres analyses.  
La partie "parsage" HTML semble aussi bien gérée.  
RSPAMD ne devrait pas être perturbé par ces anomalies et vous pourrez les detecter avec les symboles suivants:
  - "R_MIXED_CHARSET_URL"
  
RSPAMD ne permet pas la réécriture d'URL comme le fait proofpoint par exemple, mais cela est un choix technique pour éviter de casser les signatures d'un courriel comme le DKIM.  
### Faux positifs
Pas de faux positif connu.

## Protéger vous des anomalies qui vont induire en erreur l'utilisateur <a name="reply"></a>
### Description
Un attaquant va souvent chercher des subterfuges pour pousser l'utilisateur à effectuer une action qu'il souhaite.  
Au dela du message contenu dans les courriels, il peut essayer d'utiliser des anomalies pour cacher certaines informations.
### Exemple de configuration
RSPAMD contient par défaut beaucoup de symboles qui permettent d'identifier des anomalies suspectes:
  - "MIME_DOUBLE_BAD_EXTENSION": double extension
  - "MIME_UNKNOWN": utilisation d'un mime type inexistant
  - "MIME_MA_MISSING_TEXT": l'expéditeur transmet un message qui devrait contenir une version texte et html du message, mais il manque la version texte.
  - "MULTIPLE_UNIQUE_HEADERS": il y a plusieurs occurences d'une en-tête qui devrait être unique.
  - "MISSING_SUBJECT": il n'y a pas de sujet
  - "FORGED_GENERIC_RECEIVED": l'en-tête "received" a été usurpée
  - "MISSING_DATE": il n'y a pas de date
  - "MISSING_FROM": il n'y a pas de FROM (en dehors de l'enveloppe)
  - "MISSING_MIME_VERSION": il n'y a pas la version MIME
  - "MISSING_TO": il n'y a pas de TO (en dehors de l'enveloppe)
  - "INVALID_FROM_8BIT": il y a des caractères suspects dans le FROM
  - "RCVD_ILLEGAL_CHARS": il y a des caractères suspects dans les en-têtes
  - "BROKEN_HEADERS": les en-têtes semblent mal formées
  - "BROKEN_CONTENT_TYPE": le content-type semble mal formées
  - "MIME_HEADER_CTYPE_ONLY": il manque des informations de mime part.
  - "DATE_IN_PAST": la date du courriel est ancienne.
  - "DATE_IN_FUTURE": la date du courriel est dans le futur.
  - "R_BAD_CTE_7BIT": content-transfer-encoding n'est pas valide
  - "FROM_NAME_EXCESS_SPACE": le "display name" a un nombre très important d'espace.
  - "R_MISSING_CHARSET": le charset n'a pas été spécifié.
  - "R_MIXED_CHARSET": il y a une utilisation de différents "charset".
  - "R_SUSPICIOUS_URL": l'URL semble obfusquée
  - "OMOGRAPH_URL": l'URL pourrait être trompeuse
  - "*_EXCESS_BASE64": une en-tête utilise trop d'encodage
  - "*_EXCESS_QP": une en-tête utilise trop d'encodage
De plus, vous pouvez aussi prendre en compte la partie [Verifier l'identité des courriels entrants](rules/ident.md#in)
### Faux positifs
Selon le score que vous allez mettre, il peut y avoir des faux positifs, il vaut mieux donc tester la règle sur le "worker" de test pour identifier les risques de faux positifs avant d'activer en production.

## Protéger vous des anomalies qui pourrait exploiter une faille logiciel <a name="cve"></a>
### Description
Il peut exister des failles dans vos lecteurs de courriel (exemple: https://www.mailsploit.com), ou dans votre serveur de courriel.  
Il est donc important de mettre à jour l'ensemble des éléments de la messagerie (client/serveur).  

### Exemple de configuration
Pour la partie serveur, si vous êtes parano, vous pouvez compiler en mode hardening, mettre en place un profil apparmor et secomp sur votre docker (mais cela demande des connaissances importantes).

### Faux positifs
Aucun

