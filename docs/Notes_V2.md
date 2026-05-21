# V2

Cette deuxième version est plus complète que la précédente : elle intègre plus de features.

## Contraintes

La deuxième version du projet, nous suivrons les contraintes suivantes (décidée en call) : 

1. La source d'entropie sera une liste de captures d'écran d'un vidéo de lampe à lave.
2. L'image sert de source d'entropie en tant que seed, et non comme la clé en elle même.
3. Le stockage de la data sera fait en local sur nos machines.
4. Les images seront en noir et blanc pour réduire la taille des clés.
5. Les données cryptées seront un document .txt

## Architecture

L'architecture de la première version du projet sera principalement constituée de 4 scripts :

1. Un script `setup.py` : chargé de générer 2 grands nombres à partir de la photo publique. 
2. Un script `rsa_cles.py` : chargé de générer les clés RSA à partir des 2 grands nombres.
3. Un script `cryptage.py` : chargé de crypter de la donnée à partir de la clé publique du destinataire.
4. Un script `décryptage.py` : charge de décrypter un message reçu à partir de la clé privée. 
5. Un script `main.py` : chargé d'exécuter tous les scripts depuis la racine + gestion des interruptions lors du changement de clés.

## Pipeline

Diagramme pour visualiser la pipeline de main.py :

```
image lava lamp
        ↓ image_to_bytes()
bytes brutes
        ↓ seed_vers_grands_entiers()
grands entiers (entropy seed)
        ↓ generer_cles_rsa()
clé RSA
        ↓ chiffrer() / dechiffrer()
message_chiffre.txt  →  message_dechiffre.txt
```
