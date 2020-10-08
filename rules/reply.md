# Règles de protection contre le phishing par réponse courriel
Tests ACSS concernés n°: 78  
Date Creation: 24/09/2020  
Date dernière mise à jour: 24/09/2020  
Facilité de mise en place: Simple ~~/ Moyen / Complexe~~  


## Protéger vous contre le phishing par réponse courriel
### Description
Le scenario est simple, vous recevez un courriel qui se fait passer pour le service support, vous indiquant un problème avec votre compte, afin de leur indiquer votre login et mot de passe pour règler la situation.  
Dans la grande majorité des cas, le courriel est transmis par une boite compromise ou un service d'envoi de courriel compromis, afin de pouvoir recevoir la réponse, l'attaquant va ajouter une en-tête 'reply-to' qui va permettre lors de la réponse de la victime de recevoir la réponse sur l'adresse courriel indiquée dans ce champ.  
Dans de nombreux cas, l'adresse courriel est créée sur un service gratuit ou un service en promotion (2 mois gratuit puis xxx€...).
Cette technique est relativement facile à détecter:
  - Le domaine de réponse (REPLY-TO) n'est pas le même que le domaine du FROM;
  - S'il s'agit d'un service d'envoi de courriel compromis, souvent le message ID (MID) aura un domaine different;
  - L'attaquant va avoir tendance à utiliser un "display name" pour cacher la vrai identité du FROM;
  - Il y a aura dans mots clés dans le courriel en lien avec:
     - l'objectif: 'mot de passe|password', 'identifiant', 'login|user|utilisateur', ...
     - le mensonge: 'quota', 'réinitialiser', 'plein', 'securite', 'illegal', ...
     - la signature: 'support', 'helpdesk', 'admin', ...

### Exemple de configuration
Nous avons créer un composite ([local.d/composites.conf](/rspamd-docker/data/conf/rspamd/local.d/composites.conf#L5-L8)) pour créer cette règle sur le symbole: "PHISHING_REPLY".  
Vous pouvez aussi utilisez les symboles suivants:  
  - REPLYTO_DOM_NEQ_FROM_DOM: Le domaine reply-to est different du domaine FROM;
  - FREEMAIL_REPLYTO: le courriel utilisé dans reply-to est une adresse gratuite
  - FROM_HAS_DN: le FROM à un 'display name'
  
Ainsi que les symboles évoqués dans l'[usurpation d'identité](rules/ident.md#in).

### Faux positifs
Si vous n'avez pas identifié un serveur qui transmet des courriels pour votre domaine de manière légitime et qui n'est pas dans le SPF ou qui n'a pas la clé de chiffrement DKIM.  


