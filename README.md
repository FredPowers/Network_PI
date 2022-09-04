# Network_PI
A little network investigation


  <#
.NOTES
	NAME:	Scan_Reseau.ps1
    VERSION : 1.0  17/05/2022
    VERSION : 1.2  04/09/2022
	AUTHOR:	Frédéric Puren


VERSION 1.1 :

- Amélioration du script en intégrant une fonction pour le calcul réseau.
- Ajout du scope d'adresse IP d'un second réseau si un VPN est connecté.


VERSION 1.2 :

- Renommage du script Scan_réseau et intégration d'autres fonctionnalitées.
- amélioration du temps de scan en faisant appel à Get-WmiObject (2 min 30 s environ pour un réseau en /24)
- intégration du fichier liste_OUI.txt (Organizationally Unique Identifier) pour la liste des fabricants des cartes réseaux selon les adresses Mac.
- Le fichier Liste_OUI.txt doit être placé dans le même répertoire que le script.

  Sources : 

  faire un menu : https://wiki-tech.io/Scripting/Powershell/Menu

  séparer des chaines de caractère : https://www.it-connect.fr/powershell-et-split-decouper-une-chaine-de-caracteres/

  extraire une chaine de caractère : https://www.it-connect.fr/powershell-et-substring-extraire-une-chaine-dune-chaine/

  padleft, padright : https://4sysops.com/archives/how-to-add-leading-and-ending-zeroes-to-strings-in-powershell/

  créer une fonction : https://techexpert.tips/fr/powershell-fr/powershell-creation-dune-fonction/
  
  Scan réseau en /24 : https://www.pentest.school/blog/scanner-un-reseau-avec-powershell

  Ping avec Get-WmiObject : https://powershell.one/wmi/root/cimv2/win32_pingstatus

  Scan de ports : https://jonlabelle.com/snippets/view/powershell/powershell-script-to-scan-open-ports

  Localisation d'une IP : https://www.1formatik.com/7467/comment-localiser-une-adresse-ip-avec-powershell
#>

<img width="346" alt="0" src="https://user-images.githubusercontent.com/105367565/188311019-55cc81d5-6fb5-4fcc-ae04-d9a4ae55ecaa.png">



  “1. Scan de tout le réseau”
- detecte le réseau sur lequel vous vous trouver et scan toutes les machines de celui-ci.
- Génère un fichier "résultat_scan.txt" dans le même répertoire que le script.

<img width="517" alt="1" src="https://user-images.githubusercontent.com/105367565/188311028-a1294840-79e7-4c6e-b6af-adb801ec585f.png">


  "2. Scan des Ports ouverts sur tout le réseau"
- detecte le réseau sur lequel vous vous trouver et scan certains ports ( il est possible d'ajouter des ports en modifiants le script)

<img width="468" alt="2" src="https://user-images.githubusercontent.com/105367565/188311042-e9101c74-58fc-4b0e-95c9-2c2a05e32d7f.png">


  "3. Scan réseau sur une plage IP spécifique"
Idem que le 1. mais vous choississez la premiere et derniere IP pour le scan.


  "4. Scan des ports sur une plage IP spécifique"
Idem que le 2 mais vous choississez la premiere et derniere IP pour le scan des ports.


  "5. Enregistrement DNS + Localisation de l'IP"
  
  <img width="702" alt="5" src="https://user-images.githubusercontent.com/105367565/188311075-a6d05a4d-1a18-4db2-9309-30af0218d20b.png">

  
  "6. Afficher les mots de passe WiFi enregistrés"
  
  <img width="406" alt="6" src="https://user-images.githubusercontent.com/105367565/188311082-1d8f4e32-9a86-473c-ba64-c2e480772138.png">

  "7. Recherche Google Dorks"
  
  <img width="575" alt="7" src="https://user-images.githubusercontent.com/105367565/188311176-7abde852-4286-44ab-a4cd-01cf9154a0d9.png">

  
  "8. Traceroute avec localisation"
  
  <img width="303" alt="8" src="https://user-images.githubusercontent.com/105367565/188311092-c5d2a0fa-8e0b-4164-abd7-e8e414f919fa.png">

  "9. Vérifier si des partages sont actifs"
  
  <img width="665" alt="9" src="https://user-images.githubusercontent.com/105367565/188311098-75c1f41c-e7b8-4db6-b8f2-1427cc121ade.png">

<img width="537" alt="9a" src="https://user-images.githubusercontent.com/105367565/188311105-936a12cf-4d33-4055-b02e-a961e1a69564.png">

  "10.Scan Windows Defender"
  
  <img width="323" alt="10" src="https://user-images.githubusercontent.com/105367565/188311116-24be335a-e076-4d39-a871-272e4e652fd7.png">

  "11.Vérifier l'historique Powershell"
affiche les dernière commande powershell exécuter (4096 max par défaut)

<img width="537" alt="11" src="https://user-images.githubusercontent.com/105367565/188311121-46c7522b-c5d8-43ea-8755-59abd1b34370.png">



