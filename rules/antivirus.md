# Mise en place d'une solution AntiVirus
Tests ACSS concernés n°: 2, 3, 4  
Date Creation: 22/09/2020  
Date dernière mise à jour: 22/09/2020  
Facilité de mise en place: Simple ~~/ Moyen / Complexe~~  

Les exemples de configuration (ci-dessous) sont basés sur clamav (https://www.clamav.net/).  
Si vous ne souhaitez pas utiliser clamav, vous pouvez vous en inspirer pour l'adapter à votre solution antivirus.


##  Clamav
### Présentation
Clamav est un antivirus opensource très puissant qui permet offre de nombreuses possibilités de personnalisation.  
Clamav scan un fichier et selon le type, il pourra en extraire des objets et/ou des sous fichiers. Il va verifier chacune de ces signatures sur chaque fichiers et objets/sous fichiers extraits.  
Par exemple, si vous avez un zip, qui contient un fichier office (doc) qui contient un macro, qui va ecrire un fichier executable sur le disque puis l'executer, clamav sera en mesure d'extraire le fichier office, l'ensemble des macros et potentiellement le fichier executable.  
Sur chacun de ces objets il va effectuer une recherche de l'ensemble de ces signatures.  

Clamav permet de créer des signatures dans son format, mais surtout il peut importer des signatures au format YARA (https://yara.readthedocs.io/en/stable/writingrules.html).  
### Installation
#### Docker
Le plus simple pour installer clamav est d'utiliser le docker qui emportera l'ensemble des éléments de protection de la messagerie (rspamd, redis, olefy, clamav, ...).  
Si vous ne connaissez pas encore la technologie docker, il est temps de s'y mettre: https://www.docker.com/ .   
Si vous le souhaitez vous pouvez juste prendre le docker clamav et l'integrer dans votre solution existante.  
Le docker inclus:
  - la dernière version de clamav (au 22/09 - version 0.103.0) compilée en mode "hardening" (https://wiki.debian.org/Hardening), ce qui vous protegera à minima même si une faille memoire était découverte;  
  - certaines signatures non officielles;
  - des règles yara spécifiques à la messagerie.
#### Package
Clamav est disponible sur les principales distributions linux. De plus vous pouvez utiliser les signatures non officielles qui sont aussi souvent disponibles.
### Fonctionnalités
Clamav possède un outil de mise à jour des signatures nommé "freshclam".
#### Signatures de base
Il s'agit des signatures publiques editées par clamav
#### Signatures non officielles
Il s'agit des signatures publiques editées par des tiers (abuse.ch, malwarepatrol, ...).  
Vous pouvez utiliser le script de mise à jour des signatures tiers inclus dans votre distribution ou https://github.com/extremeshok/clamav-unofficial-sigs .  
#### Règles Yara
La plupart des règles yara sont compatibles avec clamav, à l'exception de celles utilisant des modules yara spécifiques comme: math, pe, ...  
Vous pouvez trouver des signatures yara sur de nombreux sites ou dépots, l'officiel est: https://github.com/Yara-Rules/rules .
### Configuration
Clamav s'integre dans Rspamd avec le daemon "clamd" via le fichier de configuration rspamd: "local.d/antivirus.conf".

