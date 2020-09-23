# Règles de protection contre l'usurpation d'identité
Tests ACSS concernés n°: 70,79,80,81,85,98,99,102,105,108,119,120  
Date Creation: 22/09/2020  
Date dernière mise à jour: 22/09/2020  
Facilité de mise en place: Simple ~~/ Moyen / Complexe~~  

Règles:
1. [Protéger votre identité sur internet](#my)
2. [Protéger l'identité de vos utilisateurs](#user)
3. [Verifier l'identité des courriels entrants](#in)

## Protéger votre identité sur internet <a name="my"></a>
### Description
Cette règle permet d'éviter qu'une personne sur internet transmette des courriels en provenance ("d'apparence") de chez vous.  
Il existe 3 protocoles de protection afin de realiser cette protection:
  - SPF (https://fr.wikipedia.org/wiki/Sender_Policy_Framework): il s'agit d'un enregistrement DNS type 'TXT' à mettre dans votre 'NS' de domaine.
    - Vous pouvez génerer l'enregistrement à mettre dans le 'TXT' depuis le lien suivant: https://www.spfwizard.net/
    - Une fois l'enregistrement mis en place vous pouvez le tester avec le lien suivant: https://app.dmarcanalyzer.com/dns/spf?simple=
    - Il existe plusieurs modes:
      - "-all" == fail (non conforme devrait être rejeté)
      - "~all" == softfail (non conforme devrait être indiqué)
      - "?all" == neutral (devrait être accepté)
   - DKIM (https://fr.wikipedia.org/wiki/DomainKeys_Identified_Mail): il permet de signer un message afin que le recepteur à partir de la clé publique puisse verifier l'integrité et l'origine.
     - Une fois l'enregistrement 'TXT' mis en place vous pouvez le tester avec le lien suivant: https://www.dmarcanalyzer.com/fr/dkim-4/verification-de-dkim-record/
   - DMARC (https://fr.wikipedia.org/wiki/DMARC): indique la marche à suivre au récepteur en cas d'échec sur la verification SPF et DKIM. Permet d'avoir un rapport en xml sur les erreurs de validation SPF et DKIM (seulement si le recepteur utilise DMARC).
     - Une fois l'enregistrement 'TXT' mis en place vous pouvez le tester avec le lien suivant: https://www.dmarcanalyzer.com/fr/dmarc-4/verification-de-dmarc-record/
   - ARC (https://groupes.renater.fr/wiki/smtp-fr/public/arc): il permet d'autoriser le contournement de la conformité DMARC/SPF/DKIM par une chaine spécifique de relais de confiance.

Il est important d'avoir au minimum du SPF pour votre domaine. Si vous souhaitez identifier qui usurpe l'identité de votre domaine alors DMARC pourra vous aider.
### Exemple de configuration
Pour la partie SPF, seul le DNS est à configurer.  
Pour la partie DKIM, il faut generer une clé publique et privée, et mettre la publique sur votre DNS, enfin il faut ajouter une solution qui va signer vos courriels sortants avec la clé DKIM privé, RSPAMD peut le faire pour vous avec son module "DKIM signing" (https://rspamd.com/doc/modules/dkim_signing.html).  
Pour la partie DMARC, en plus du DNS, il faut créer une boite courriel pour la reception des rapports.
Pour la partie ARC vous pouvez utiliser le module ARC de Rspamd (https://rspamd.com/doc/modules/arc.html).
### Faux positifs
Si vous n'avez pas identifié un serveur qui transmet des courriels pour votre domaine de manière légitime et qui n'est pas dans le SPF ou qui n'a pas la clé de chiffrement DKIM.  

## Protéger l'identité de vos utilisateurs <a name="user"></a>
### Description
Cette règle permet d'eviter qu'un utilisateur (ou un attaquant) sur votre réseau usurpe l'identité d'une autre personne de votre structure. Elle permet aussi en cas de boite compromise qu'un attaquant transmette des courriels avec un 'FROM' sans lien avec votre domaine.
Pour se faire, vous devez utiliser l'authentification "smtp" afin de s'assurer que l'utilisateur authentifié est le meme que celui dans le champs 'FROM' (expéditeur).
### Exemple de configuration
Sur postfix vous allez devoir activer l'authentification SASL sur votre SMTP sortant et créer une "map" de correlation entre login et adresse courriel.
Vous trouverez plus d'informations sur le lien suivant: https://stackoverflow.com/questions/38577868/postfix-check-the-from-address-field-matches-the-authenticated-username-or-other
### Faux positifs
Pas de faux positif connu.

## Haute disponibilité <a name="in"></a>
### Description
Cette règle permet de verifier qu'un courriel entrant n'a pas une identité usurpée.
### Exemple de configuration
Nous allons utiliser RSPAMD pour effectuer ces verifications, a vous d'ajuster le score si vous constatez que vos protections laissent passer des courriels usurpés.
Voici les principales vérifications à effectuer:
  - Domaine qui n'existe pas ou qui n'a pas de MX (donc pas de possibilité de réponse):
    - Module MX check (https://rspamd.com/doc/modules/mx_check.html)
      - Symboles:  MX_INVALID (score par défaut: 0.5) ou MX_MISSING (score par défaut: 3.5)
    - Module Hfilter (https://rspamd.com/doc/modules/hfilter.html)
      - Symboles: effectuez une recherche 'hfilter' dans l'interface web dans la partie "symbols".
  - Emeteur qui n'est pas conforme à l'enregistrement SPF
    - Symboles: R_SPF_SOFTFAIL / R_SPF_SOFTFAIL / R_SPF_FAIL / SPF_FAIL_NO_DKIM / AUTH_NA
  - Emeteur a une signature DKIM non valide:
    - Symbole: R_DKIM_REJECT
  - Emeteur qui n'est pas conforme à l'enregistrement DMARC
    - Symboles: DMARC_POLICY_ALLOW_WITH_FAILURES / DMARC_POLICY_REJECT / DMARC_POLICY_QUARANTINE / DMARC_POLICY_SOFTFAIL
  - Emeteur qui n'est pas conforme à l'enregistrement ARC
    - Symbole: ARC_INVALID
  - l'ID de message (s'il y en a un) peut contenir des anomalies suspectes:
    - Symboles: MISSING_MID/MID_DOMAIN_NEQ_FROM_DOMAIN/MID_CONTAINS_FROM/MID_RHS_NOT_FQDN/
  - Le FROM de l'enveloppe et le FROM du contenu peuvent avoir des anomalies pour tromper le recepteur:
    - Symboles: FROM_NEQ_ENVFROM / FORGED_SENDER / MISSING_FROM / MULTIPLE_FROM / MULTIPLE_UNIQUE_HEADERS / FROM_EXCESS_BASE64 / FROM_EXCESS_QP
  - LE 'display name' (le nom qui apparait à la place de l'adresse brute) peut avoir des éléments suseptibles d'être trompeur:
    - Symboles: SPOOF_DISPLAY_NAME / FROM_NAME_HAS_TITLE / FROM_DN_EQ_ADDR / FROM_NAME_EXCESS_SPACE / FROM_HAS_DN
  - Le FROM contient des caractères illisibles ou spécifiques:
    - Symbole: INVALID_FROM_8BIT
  - Réputation du FROM (attention il ne s'agit plus vraiment de verifier l'usurpation d'identité):
    - Symboles: RBL_MAILSPIKE_*/RBL_SPAMHAUS_*/RBL_SENDERSCORE/RBL_BLOCKLISTDE/RBL_SEM/RBL_NIXSPAM/RBL_VIRUSFREE_BOTNET
### Faux positifs
Voici les principaux risques de faux positifs selon les règles: 
  - Domaine qui n'existe pas ou qui n'a pas de MX (donc pas de possibilité de réponse):
    - pas de risque car une domaine expediteur doit avoir un MX valide.
  - Emeteur qui n'est pas conforme à l'enregistrement SPF
    - Risque faible car si l'expediteur a configuré le SPF c'est justement pour eviter qu'on usurpe son identité, le risque est qu'il est oublié un serveur (ou un nouveau serveur), mais il corrigera rapidement normalement...
  - Emeteur a une signature DKIM non valide:
    - Risque faible car si l'expediteur a configuré le DKIM et signe ses messages, c'est pour eviter qu'on usurpe son identité.
  - Emeteur qui n'est pas conforme à l'enregistrement DMARC
    - Risque faible car si l'expediteur a configuré le DMARC c'est pour eviter qu'on usurpe son identité et être au courant.
  - Emeteur qui n'est pas conforme à l'enregistrement ARC
    - Risque faible car si l'expediteur a configuré le ARC c'est qu'il a du constater un problème de faux positifs avec SPF/DKIM/DMARC et qu'il le règle avec cette solution, afin de ne pas affaiblir sa configuration SPF/DKIM/DMARC.
  - l'ID de message (s'il y en a un) à un nom de domaine differents de l'expediteur:
    - Si vous décidez de monter le score pour ces symboles, mieux vaut verifier l'impact sur votre "worker" de test avant.Il y a un risque important sur les courriels de communication.
    - Une solution en cas de faux positifs importants est d'utiliser ce symbols dans un "composite" RSPAMD afin de lui donner plus de contexte pour eviter les faux positifs.
  - Le FROM de l'enveloppe et le FROM du contenu peuvent avoir des anomalies pour tromper le recepteur:
    - Les faux positifs devrait être faible, mais si vous décidez de monter le score pour ces symboles, mieux vaut verifier l'impact sur votre "worker" de test avant.
    - Une solution en cas de faux positifs importants est d'utiliser ce symbols dans un "composite" RSPAMD afin de lui donner plus de contexte pour eviter les faux positifs.
  - LE 'display name' (le nom qui apparait à la place de l'adresse brute) peut avoir des éléments suseptibles d'être trompeur:
   - Les faux positifs devrait être faible, mais si vous décidez de monter le score pour ces symboles, mieux vaut verifier l'impact sur votre "worker" de test avant.
   - Une solution en cas de faux positifs importants est d'utiliser ce symbols dans un "composite" RSPAMD afin de lui donner plus de contexte pour eviter les faux positifs.
  - Le FROM contient des caractères illisibles ou spécifiques:
   - Les faux positifs devrait être très faible.
  - Réputation du FROM (attention il ne s'agit plus vraiment de verifier l'usurpation d'identité):
    - Les faux positifs devrait être très faible, seulement liés aux adresses courriels légitimes ayant été compromises mais pas encore "délisté".
Selon le score que vous allez mettre, il peut y avoir des faux positifs, il vaut mieux donc tester la règle sur le "worker" de test pour identifier les risques de faux positifs avant d'activer en production.

