# Règles de protection contre les pièces jointes malicieuses
Tests ACSS concernés n°:  3,4,7 à 69, 147, 166
Date Creation: 23/09/2020  
Date dernière mise à jour: 23/09/2020  
Facilité de mise en place: Simple ~~/ Moyen / Complexe~~  

RSPAMD permet de modifier le sujet d'un courriel, ajouter des en-têtes, ajouter un message dans le corp du courriel, mais il n'est pas possible de supprimer un élément du courriel comme une pièce jointe.  

Règles:
1. [Rejeter les pièces jointes dangereuses](#reject)
2. [Filtrer les pièces jointes susceptibles d'être dangereuses](#filter)
3. [Filtrer les pièces jointes qui offrent un risque de contournement de votre politique](#filter2)

## Rejeter les pièces jointes dangereuses <a name="reject"></a>
### Description
L'objectif de cette règle est de filtrer les courriels avec des pieces jointes dont l'extension est dangereuse.  

Veuillez trouver la liste des extensions "interdites" (car normalement aucune personne exterieur ne devrait vous transmettre ce type de fichier) que les attaquants utilisent le plus:
  - PE (permet de directement transmettre une charge -- PE == exe, dll, pif, ... [https://fr.wikipedia.org/wiki/Portable_Executable])
  - MS* (Installateur windows)
  - HTA (script vb/js)
  - VB*/WS* (script vb)
  - PS*/MSH (script powershell)
  - BAT/CMD/BTM/... (script batch windows)
  - MA* (macro)
  - SWF (exploitation de CVE flash
  - JAR/JNLP (execution de java)
  - JSE (execution javascript par wscript.exe)
  - CHM (permet d'integrer du script type VB)
  - HLP (fichiers help ne sont plus utilisés depuis windows xp)
  - LNK (Exploitation de CVE ou )
  - URL (URL)
  - INF (autorun ou URI)
  - SCT (execution de commande ou URI)
  - SDB (Execution commande)
  - ACE (format d'archive ancienne que certaines protections ne savent gerer)
  - CAB (archive windows)
  - appref-ms/gadget (installation d'application par téléchargement)
  - Toutes les extensions dont le lecteur peut avoir une cve (exemples: video => cve VLC; image "otf" => cve windows font, ...) et qui ne dervait pas être transmis par courriel.

Afin d'identifier les nouveautés vous pouvez regarder sur virustotal ou les sandbox en ligne les extensions des fichiers sousmis (meme si cela ne provient pas forcement d'un courriel).
### Exemple de configuration
Le filtrage des extensions à risque s'effectue avec le module "Mime types" (https://rspamd.com/doc/modules/mime_types.html).
Vous trouverez la configuration proposé dans le fichier "local.d/mime_types_group.conf", a vous d'adapter le score en fonction de votre politique, si vous souhaitez:
  - que le courriel contenant une piece jointe spécifique, par exemple "exe" (exécutable) soit rejeté directement alors mettez un score > 15 (à adapter en fonction de votre configuration dans le fichier "local.d/actions.conf").
  - que le courriel contenant une piece jointe spécifique, par exemple "py" (script python) ne soit pas automatiquement rejeté mais qu'il soit considéré comme suspect mettez un score entre 1 et 7 (à adapter en fonction de votre configuration dans le fichier "local.d/actions.conf").

### Faux positifs
Avec vos logs de messagerie, vous pouvez essayer d'identifier si les extensions que vous allez bannir sont utilisées ou non.
Si certaines pieces jointes dans la liste ci-dessous doivent être transmis par un partenaire de confiance, vous pouvez mettre une exception en place (attention si votre partenaire est compromis et vous transmet des courriels malicieux).
Pour realiser cette exception utilisez les exemples suivants: 
  - https://rspamd.com/doc/modules/mime_types.html#user-settings-usage (selon l'expediteur);
  - https://rspamd.com/doc/modules/mime_types.html#filename-whitelist (selon le nom du fichier).
Vous pouvez aussi, transmettre un message à l'expediteur pour lui indiquer que votre politique de sécurité n'accepte pas ce type de piece jointe (attention à ne pas offrir aussi l'oportunité pour un attaquant d'identifier votre politique de filtrage afin de mieux pouvoir la contourner).

## Filtrer les pièces jointes susceptibles d'être dangereuses <a name="filter"></a>
### Description
Cette règle permet de filtrer les courriels contant une piece jointe avec une extension autorisée avec un contenu à risque (exemple: macro dans un fichier office).  
**Attention nous n'avons pas de règles spécifiques pour les CVE, la meilleure solution est de patcher votre parc le plus rapidement possible!**  
Les extensions les plus utilisées par les pirates sont les suivantes:
  - office via l'exploitation de: macro, dde, ppaction, cve; 
  - rtf via l'exploiation d'OLE, sous-fichier ou CVE (mais qui généralement nécéssite l'utilisation d'une OLE);
  - pdf via l'exploitation de: javascript, sous-fichier, CVE;
  - javascript (js, jse) via l'exploitation de wscript.exe (qui va interpreter le fichier si l'utilisateur clique deux fois dessus);
    - Il est difficile de completement interdire le js (pour le jse c'est beaucoup moins vrai) car on peut vous transmettre une archive d'un site web par exemple avec un fichier html + js + css...
  - xml via l'exploitation d'une XXE
  - html via l'exploitation d'un script (vbscript/javascript)
  - js (javascript)
  - Toutes les extensions dont le lecteur à une cve (exemples: video => cve VLC; image "otf" => cve; ): tenez vous informé des CVE afin de bloquer les extensions le temps que votre parc soit à jour.
  
Parfois l'attaquant ne va rien mettre dans le corp du courriel (sauf éventuellement "ouvrez la piece jointe") et va utiliser un fichier PDF, DOC, RTF pour transmettre le message afin que vous protection ne soit pas en mesure d'identifier une URL malicieuse (dans la majorité des cas).  
Certains peuvent aller jusqu'a integrer le message dans une image (png, jpeg, ...), mais dans ce cas, s'il y a une URL, elle ne sera pas "cliquable".
Malheureusement dans ce deux derniers cas, il est très complexe d'arriver à extraire l'URL malicieuse de manière simple.
### Exemple de configuration
Il existe plusieurs possibilités pour effectuer ces filtrages:
  - Office:
    - Règle Yara "office.yara" dans clamav va détecter tous les risques liés à office: dde, macro, ppaction.
    - Utilisation de Olefy (deamon qui utilise oletools) qui permet d'obtenir des informations sur le macro d'un fichier office et vous permettra de filtrer avec finesse les MACRO (https://rspamd.com/doc/modules/external_services.html#oletools-extended-mode)
  - RTF
    - Règle Yara "office.yara" dans clamav va détecter tous les risques liés à rtf: Ole, EmbeddedFiles, potentiel shellcode (cas CVE).
    - A ce jour (23/09/2020), olefy ne gère pas les fichiers RTF alors que oletools sait les analyser. Il est donc possible que prochainement, l'analyse de RTF soit possible avec olefy.
  - PDF:
    - Règle YARA "pdf.yara" dans clamav va détecter tous les risques liés aux pdf: fileexport, EmbeddedFiles ,XFA & JS, JS, structure PDF invalide, metadata suspect.
  - javascript & HTML:
    - Règle YARA "javascript.yara" dans clamav va détecter tous les risques liés au javascript: obfuscation, fonctions à risque: ActiveX, eval, connexion http(s).
    - Règle YARA "vb.yara" dans clamav va détecter tous les risques liés au vbscript dans html: obfuscation, fonctions à risque: ActiveX, eval, connexion http(s).
  - XML:
    - Règle YARA "xml.yara" dans clamav va détecter tous les risques liés au XML: XXE (https://en.wikipedia.org/wiki/XML_external_entity_attack).
### Faux positifs
#### Macro office
Il est très rare de voir des fichiers office avec du DDE ou ppaction. Par contre, on peut trouver des macros, mais la encore rarement des macros avec de l'obfuscation ou appelant des fonctions de téléchargement ou d'écriture sur le disque.  
Si vous avez un tiers de confiance (exterieur) identifié qui vous transmet des fichiers macro, alors utilisez une exception dans le fichier "local.d/settings.conf" (https://rspamd.com/doc/configuration/settings.html#settings-structure).  
Attention si l'utilisateur de confiance est compromis, vous etes suseptible de recevoir des malwares par courriel qui ne seront pas identifié.  
  
Si vous souhaitez ne pas filtrer tous les macro, désactiver les règles Yara "office_document_vba" et "Office_AutoOpen_Macro" dans le fichier office.yara. Puis effectuez un filtrage plus fin en utilisant "olefy" via le "pattern matching" (https://rspamd.com/doc/modules/external_services.html#oletools-extended-mode).  
Vous trouverez la liste des mots clés qu'il est possible de chercher par pattern dans le code d'oletools: https://github.com/decalage2/oletools/blob/master/oletools/olevba.py#L658
#### RTF
Il est très rare de voir des RTF légitimes avec du contenu OLE ou un fichier inseré.  
Si vous identifiez une règle qui cause trop de faux positif, vous pouvez la désactiver dans le fichier "rtf.yara", et nous sommes interessé pour la connaitre afin de pouvoir potentiellement l'ameliorer.
#### PDF
Il est possible de voir des PDF avec du javascript (surement sur des documents que l'on peut remplir), par contre il est très rare de voir des fichiers inserés, de l'exportfile ou des structures invalides (utilisés pour contourner ou cve).  
Si vous identifiez une règle qui cause trop de faux positif, vous pouvez la désactiver dans le fichier "pdf.yara", et nous sommes interessé pour la connaitre afin de pouvoir potentiellement l'ameliorer.
#### Javascript & HTML
Il est possible d'avoir du javascript attaché à un courriel, mais il est suspect d'utiliser des fonctions ActiveX, eval(), ou de connexion http(s).  
Si vous identifiez une règle qui cause trop de faux positif, vous pouvez la désactiver dans le fichier "javascript.yara", et nous sommes interessé pour la connaitre afin de pouvoir potentiellement l'ameliorer.
Il est très suspect d'avoir du vbscript dans un fichier HTML, cependant vous pouvez désactiver dans le fichier "vb.yara", et nous sommes interessé pour connaitre les faux positifs afin de pouvoir potentiellement ameliorer la règle.
#### XML
L'utilisation de XXE légitime dans un XML doit être très rare, cependant vous pouvez désactiver dans le fichier "xxe.yara", et nous sommes interessé pour connaitre les faux positifs afin de pouvoir potentiellement ameliorer la règle.

## Filtrer les pièces jointes susceptibles d'être dangereuses <a name="filter2"></a>
### Description
Cette règle permet de filtrer les courriels contant une piece jointe autorisée qui pourrait permettre de contourner vos protections.
Les extensions les plus utilisées par les pirates sont les suivantes:
  - zip/archive:
    - avec mot de passe contenu dans le courriel
    - qui contient un très gros fichier qui dépasse le seuil de scan
    - qui contient un nombre de fichiers qui dépasse le seuil de scan
    - qui contient une "enfilade" de zip qui dépasse le seuil de scan
  - rtf (souvent renommé en .doc) avec obfuscation sur son en-tête afin que vos protections n'identifie pas qu'il s'agit d'un fichier RTF.
  - office avec mot de passe contenu dans le courriel
  - pdf avec mot de passe contenu dans le courriel
  - courriel attaché (eml, msg) contenant l'élement malicieux
### Exemple de configuration
Il existe plusieurs possibilités pour effectuer ces filtrages:
  - Clamav:
    - Par défaut clamav scan l'interieur des fichiers courriels (eml, msg) alors que RSPAMD ne gère que eml et il est facile de contourner sa détection "eml" (voir l'issue: https://github.com/rspamd/rspamd/issues/3487). C'est pour cela que nous avons ajouté des règles yara pour détecter les types de fichiers interdits (PE, ...), pour plus d'informations regardez dans le repertoire "data/conf/clamav-rules/".
    - Clamd.conf avec "AlertEncrypted yes" et Symboles RSPAMD: "CLAM_DETECT_ENCRYPTED" et "CLAM_DETECT_ENCRYPTED_WITH_PASS"
      - filtrage documents (pdf, office) avec mot de passe et zip avec mot de passe
    - Clamd.conf avec "AlertExceedsMax yes" et "local.d/antivirus.conf" avec "patterns_fail" puis déclenchement sur symbole RSPAMD "CLAM_EXCEEDED" ("local.d/composites.conf"):
      - Filtrage archive:
        - qui contient un très gros fichier qui dépasse le seuil de scan
        - qui contient un nombre de fichiers qui dépasse le seuil de scan
        - qui contient une "enfilade" de zip qui dépasse le seuil de scan
    - Règle Yara "office.yara" dans clamav va détecter tous les risques liés à l'obfuscation de rtf.
  - RSPAMD:
    - Symbole "MIME_ARCHIVE_IN_ARCHIVE"
      - Filtrage archive qui contient une "enfilade" de zip qui dépasse le seuil de scan

### Faux positifs
Pour les documents et zip avec mot de passe, vous pouvez baisser le score "CLAM_DETECT_ENCRYPTED" et maintenir un score élevé sur "CLAM_DETECT_ENCRYPTED_WITH_PASS" qui indique qu'une pièce jointe est avec un mot de passe, et qu'un mot de passe semble être dans le corp du message.
