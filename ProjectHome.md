# Code obfuscator #
**Définition de Wikipédia**
L'obfuscation est tout d'abord un moyen de protéger les investissements de développement d'un logiciel par des techniques de génération de code objet rendant plus difficile la rétro-ingénierie.
## Contexte ##
Dans le cadre d'un projet de recherche, le groupe de compétences IT Security veut rendre difficile le reverse-engineering d'un programme executable.
En effet des utilitaires comme objdump ou IDAPro permettent facilement de trouver le code assembleur et de là retrouver des algorithmes industriels qui sont peut-être des secrets de fabrications d'une entreprise.
## Objectif du projet ##
Créer un obfuscateur de code qui permet de changer la structure d'un programme initial pour le rendre inintelligible sans changer sa sémantique