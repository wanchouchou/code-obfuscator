## 6 octobre 2010 ##
  * Lecture de documentation sur le format ELF
> http://infocenter.arm.com/help/topic/com.arm.doc.dui0101a/DUI0101A_Elf.pdf
> http://refspecs.freestandards.org/elf/elf.pdf
> http://www.skyfree.org/linux/references/ELF_Format.pdf
  * Lecture de documentation sur le langage assembleur ARM
> http://marine.edu.ups-tlse.fr/~rochange/ISI1A/PolycopARM.pdf
  * Lecture de documentation sur des techniques d’obfuscation en assembleur
> http://www.unixgarden.com/index.php/securite/techniques-dobfuscation-de-code%C2%A0-chiffrer-du-clair-avec-du-clair
  * Lecture de documentation sur le reverse engineering d’exécutables pour ARM
> http://www.codebreakers-journal.com/downloads/cbj/2006/CBM_3_1_2006_Fogie_Embedded_Reverse_Engineering.pdf

## 12 octobre 2010 ##
  * Réalisation d’une première version du cahier des charges

## 13 octobre 2010 ##
  * Correction du cahier des charges
  * Lecture du document reçu lors de la dernière séance

## 15 octobre 2010 ##
  * Rendu du cahier des charges

## 18-19 octobre 2010 ##
  * Préparation pour la présentation du cahier des charges

## 25-31 octobre 2010 ##
  * Recherche de documentation sur obfuscation binaire
> http://palisade.plynt.com/issues/2005Aug/code-obfuscation/
> http://www.cs.arizona.edu/~collberg/Research/Publications/CollbergThomborsonLow97a/A4.pdf


## 3 novembre 2010 ##
  * Désassemblage d'un simple programme c sur x86, étude du fichier exécutable
> http://www.haypocalc.com/wiki/Vocabulaire_de_l'assembleur_Intel_x86
> http://www.commentcamarche.net/faq/9058-installer-un-emulateur-arm-gratuit
> http://www.thefreecountry.com/emulators/arm.shtml

## 5 novembre 2010 ##
  * Installation d'un compilateur croisé linux-arm, étude d'un programme simple avec readelf et objdump
> http://www.ibm.com/developerworks/linux/library/l-arm-toolchain/index.html?ca=drs-
  * Plus d'informations sur le format ELF
> http://www.ouah.org/RevEng/x430.htm

## 10 novembre 2010 ##
  * Manipulation de fichiers ELF avec gHex
  * Essais avec la librairie elf.h
> http://www.student.cs.uwaterloo.ca/~cs350/common/os161-src-html/elf_8h.html

## 17-19 novembre 2010 ##
  * Manipulation de fichiers ELF avec gHex (suite)
  * Essai de l'outil strip pour enlever les infos de debug
  * Codage en C d'une application pouvant afficher en hexadécimal le contenu d'un fichier binaire

## 24 novembre 2010 ##
  * Manipulation de fichiers ELF avec gHex (suite)
  * Recherche sur structure fichier ELF
  * Modifications du main et de pointeurs dans un exécutable
  * Modification du programme pour écrire dans un/plusieurs fichier(s)

## 01-03 décembre 2010 ##
  * Détermination de tous les champs qui se modifient lors de l'agrandissement du main depuis le code source
  * Ajouter de NOPs dans un fichier ELF (intel) sans créer de problèmes de pointeurs, mais le programme tourne à l'infini
  * Essais de mêmes manipulations sur exécutables ARM
  * Modification du notre programme pour effectuer tous les changements automatiquement...(en cours)

## 05-10 décembre 2010 ##
  * Etablissement d'une structure du fichier ELF
  * Modifications du code: sauvegarde des entêtes de sections dans des structures
  * Rédaction du rapport

## 13-14 décembre 2010 ##
  * Code: modifications des adresses et offsets situés dans chaque section
  * Rédaction du rapport

## 19-23 décembre 2010 ##
  * Code: insertion d'instructions fonctionne
  * Rédaction du rapport

## 3-6 janvier 2011 ##
  * Code: méthodes d'obfuscation
  * Rédaction du rapport

## 10-11 janvier 2011 ##
  * Code: méthodes d'obfuscation: obfIncPC()
  * Rédaction du rapport

## 17-22 janvier 2011 ##
  * Code: correction méthodes d'obfuscation, obfuscateMOV,obfuscateCMP

## 23-24 janvier 2010 ##
  * Code: continuation, méthodes d'obfuscation
  * Rédaction du rapport