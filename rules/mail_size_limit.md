# Règles pour la limitation de la taille maximum d'un courriel
## Description
Catégorie: filtrage/valeur_max  
Tests concernés n°: 1  
Date Creation: 18/09/2020  
Date dernière mise à jour: 18/09/2020  
Facilité de mise en place: Simple ~~/ Moyen / Complexe~~  

Cette règle permet de limiter la taille d'un courriel entrant afin d'éviter les risques suivants:
  - Le deni de service par l'épuisement des ressources (l'espace disque majoritairement);
  - Le contournement des protections qui sont souvent limitées dans la taille maximum de traitement.

## Exemple de configuration
Notre exemple est basé sur postfix (http://www.postfix.org/postconf.5.html).  
La valeur à verifier est dans la variable "message_size_limit" (du fichier "/etc/postifx/main.cf"), celle-ci doit être à "10240000" (soit 10MO).  
Cette valeur est conseillée, mais selon votre contexte vous pouvez la reduire (risque de rejet de courriel légitime) ou l'augmenter (risque de DoS ou dépassement des seuils de protection).

## Faux positifs
Vous pourriez avoir des faux positifs si des utilisateurs exterieurs vous transmette des pieces jointes légitimes dépassant ce seuil.  
Il est donc important de rejeter le message avec l'élément d'information indiqant que le courriel est trop important, ce qui permettra à l'expéditeur de savoir que la personne n'a pas reçu le courriel.  
L'interne ne devrait pas être touché par cette restriction que l'on applique sur le "MX" (entrée de courriel exterieur).  
