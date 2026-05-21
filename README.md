# 🌋 Crypto Lava Lamp

> Chiffrement RSA dont l'entropie est générée à partir d'une source visuelle aléatoire,
> inspiré de [LavaRand](https://blog.cloudflare.com/lavarand-in-production-the-nitty-gritty-technical-details/) de Cloudflare.

---

## Sommaire

- [Contexte](#contexte)
- [Installation](#installation)
- [V1 : Preuve de concept](#v1--preuve-de-concept)
- [V2 : Multi-images et chiffrement de fichier](#v2--multi-images-et-chiffrement-de-fichier)
- [V3 : Chat chiffré client-serveur (RSA + AES-256-GCM)](#v3--chat-chiffré-client-serveur-rsa--aes-256-gcm)
- [V4 : Déploiement Hardware et Réseau Local](#v4--déploiement-hardware-et-réseau-local)
- [Documentation](#documentation)

---

## Contexte

La sécurité de RSA repose entièrement sur l'imprévisibilité des nombres premiers `p` et `q`. Si ces nombres sont prévisibles, toute la sécurité s'effondre.

Cloudflare résout ce problème avec **LavaRand** : un mur de lampes à lave filmé en continu. Le chaos thermique produit une entropie physiquement imprévisible, utilisée pour seeder leur générateur de nombres aléatoires.

Ce projet reproduit ce principe en Python.

---

## Installation

**Prérequis :** Python 3.8+

```bash
git clone https://github.com/lionvb/Projet-cryptage-lampe-lave.git
cd Projet-cryptage-lampe-lave
pip install -r requirements.txt
```

---

## V1 : Preuve de concept

L'objectif de cette version est de faire fonctionner la pipeline de bout en bout avec le minimum de complexité.

### Contraintes

- Source d'entropie : **une photo statique** de lampe à lave
- Images traitées en **noir et blanc**
- Le message chiffré est un **string** (pas de fichier)
- Stockage **local**
- Scripting entièrement en **Python**

### Architecture

```
Projet-cryptage-lampe-lave/
├── docs/
│   ├── Cryptologie.md          # Explication du chiffrement RSA
│   ├── Notes_V1.md             # Décisions d'architecture de la V1
│   └── photo_lava_lamp.jpg     # Source d'entropie
├── src/
│   ├── main.py                 # Point d'entrée
│   ├── poc.py                  # Démo visuelle étape par étape
│   ├── number_generator/
│   │   └── setup.py            # Image → bytes bruts → 2 grands entiers
│   └── chiffrement_dechiffrement/
│       ├── rsa_cles.py         # Miller-Rabin + génération des clés RSA
│       ├── cryptage.py         # Chiffrement RSA + padding OAEP
│       └── decryptage.py       # Déchiffrement RSA + retrait du padding
├── requirements.txt
└── README.md
```

### Pipeline

```
photo_lava_lamp.jpg
    ↓ image_to_bytes()              rognage + réduction 50×50 + flatten
2 500 bytes bruts
    ↓ bytes_to_grands_entiers()     SHA-512 → split 2 × 32 o → 2 entiers (256 bits)
nombre_1, nombre_2
    ↓ prochain_premier()            Miller-Rabin + recherche linéaire
p, q  (~256 bits)
    ↓ generer_cles_rsa()            n=p×q, φ(n), e=65537, d=e⁻¹ mod φ(n)
clé publique (n,e)  /  clé privée (n,d)     [module ~512 bits]
    ↓ chiffrer() / dechiffrer()
message chiffré → message en clair  (affiché en console)
```

### Utilisation

```bash
cd src

# Pipeline complète
python main.py

# Démo visuelle avec matplotlib
python poc.py
```

---

## V2 : Multi-images et chiffrement de fichier

La V2 renforce l'entropie en passant d'une photo fixe à plusieurs captures d'écran d'une vidéo, et chiffre désormais un fichier `.txt` complet.

### Ce qui change

- **Entropie** : N frames d'une vidéo → une frame tirée aléatoirement parmi leurs hashs SHA-512
- **Seed** : le hash de la frame sert de graine, dérivée en 2 × 512 bits par *domain separation* (`RSA_P` / `RSA_Q`)
- **Clés RSA** : module ~1023 bits (contre ~512 bits en V1)
- **Données** : chiffrement d'un fichier `.txt`, résultat écrit dans un autre fichier `.txt`

### Contraintes

- Source d'entropie : **captures d'écran** d'une vidéo de lampe à lave (`docs/Pictures/`)
- L'image est une **seed** pour dériver les clés, pas la clé elle-même
- Images en **noir et blanc**
- Données chiffrées : **fichier `.txt`**
- Stockage **local**

### Architecture

```
Projet-cryptage-lampe-lave/
├── docs/
│   ├── Cryptologie.md
│   ├── Notes_V1.md
│   ├── Notes_V2.md             # Décisions d'architecture de la V2
│   ├── message.txt             # Fichier source à chiffrer
│   ├── message_chiffre.txt     # Produit par main.py
│   ├── message_dechiffre.txt   # Produit par main.py
│   └── Pictures/               # Frames de la vidéo lampe à lave
│       ├── lavalamp_1.png
│       └── ...
├── src/
│   ├── main.py
│   ├── number_generator/
│   │   └── setup.py            # N images → seed SHA-512 aléatoire
│   └── chiffrement_dechiffrement/
│       ├── rsa_cles.py         # + seed_vers_grands_entiers()
│       ├── cryptage.py
│       └── decryptage.py
├── requirements.txt
└── README.md
```

### Pipeline

```
docs/Pictures/  (N frames)
    ↓ images_to_bytes()             SHA-512 de chaque frame → 1 hash tiré aléatoirement
seed  (64 octets)
    ↓ seed_vers_grands_entiers()    SHA-512(seed + "RSA_P/Q" + compteur)
nombre_1, nombre_2  (512 bits chacun)
    ↓ prochain_premier()            Miller-Rabin + recherche linéaire
p, q  (~512 bits)
    ↓ generer_cles_rsa()            n=p×q, φ(n), e=65537, d=e⁻¹ mod φ(n)
clé publique (n,e)  /  clé privée (n,d)     [module ~1023 bits]
    ↓ chiffrer() / dechiffrer()
message_chiffre.txt  →  message_dechiffre.txt
```

### Utilisation

Placer le texte à chiffrer dans `docs/message.txt`, puis :

```bash
cd src
python main.py
```

---

## V3 : Chat chiffré client-serveur (RSA + AES-256-GCM)

La V3 introduit une architecture réseau complète : un serveur FastAPI sert d'oracle d'entropie et de relais, deux clients s'échangent des messages chiffrés de bout en bout via WebSocket.

### Ce qui change

- **Serveur FastAPI** : fournit la seed d'entropie (`GET /seed`), stocke les clés publiques (`POST /publickey`), relaie les messages via WebSocket (`/chat`) sans pouvoir les lire
- **Chiffrement hybride** : RSA pour l'échange de la clé de session, AES-256-GCM pour les messages
- **3 entiers dérivés** depuis la seed : `RSA_P`, `RSA_Q` pour les clés RSA, `AES_KEY` pour la clé de session

### Contraintes

- Un serveur central gère l'entropie, le registre de clés publiques et le relais
- Le chiffrement et déchiffrement se font **exclusivement côté client**
- Stockage **local**

### Architecture

```
Projet-cryptage-lampe-lave/
├── docs/
│   ├── Notes_V3.md
│   └── Pictures/
├── src/
│   ├── server/
│   │   ├── server.py               # FastAPI : /seed, /register, /publickey, WS /chat
│   │   ├── number_generator/
│   │   │   └── setup.py            # Génération de la seed côté serveur
│   │   └── Pictures/               # Frames lampe à lave du serveur
│   ├── client/
│   │   └── client.py               # Client interactif : handshake RSA + chat AES-GCM
│   ├── encrypt_decrypt/
│   │   ├── key_generator.py        # Miller-Rabin, RSA, dérivation clé AES
│   │   └── encrypt_decrypt.py      # chiffrer_RSA, dechiffrer_RSA, AES-GCM
│   └── main.py                     # Test local sans serveur
├── requirements.txt
└── README.md
```

### Pipeline

```
ALICE                        SERVEUR                        BOB
  |                             |                             |
  | génère clé_session (AES)    |                             |
  |                             |                             |
  |-- demande clé publique Bob →|                             |
  |← clé publique Bob ----------|                             |
  |                             |                             |
  | chiffre avec clé_pub_Bob    |                             |
  |-- envoie paquet chiffré ---→|-- relaie à Bob ----------→  |
  |                             |                             | déchiffre avec clé_priv_Bob
  |                             |                             | obtient clé_session
  |                             |                             |
  |←════════ canal AES (clé_session partagée) ═══════════════→|
```

### Utilisation : 3 terminaux requis

**Terminal 1 — Démarrer le serveur** (depuis la racine du projet)

```bash
uvicorn src.server.server:app --reload
```

Attendre :
```
INFO:     Uvicorn running on http://127.0.0.1:8000
```

---

**Terminal 2 — Client B, le récepteur** (à lancer avant l'initiateur)

```bash
python -m src.client.client
```

```
Username : bob
Êtes-vous l'initiateur de la session ? (o/n) : n

Connexion à ws://localhost:8000/chat?user=bob ...
Connecté en tant que bob.
```

---

**Terminal 3 — Client A, l'initiateur**

```bash
python -m src.client.client
```

```
Username : alice
Êtes-vous l'initiateur de la session ? (o/n) : o
Username du destinataire : bob

Connecté en tant que alice.
Clé AES envoyée (chiffrée RSA) à bob.

Chat en cours avec bob. Tape ton message + Entrée. Ctrl+C pour quitter.
```

Les deux clients peuvent maintenant s'écrire. Chaque message est chiffré en AES-256-GCM avant envoi, le serveur ne voit que des octets chiffrés.

**Ctrl+C** dans un terminal client pour fermer la connexion.

---
## V4 : Déploiement Hardware et Réseau Local
La V4 fait passer le projet de la théorie à la pratique en intégrant du matériel physique. Le serveur n'utilise plus d'images pré-téléchargées mais capture l'entropie en direct via une webcam pointée sur un véritable volcan. De plus, le système est déployé sur un réseau local (LAN / Partage de connexion), séparant physiquement la machine serveur des machines clientes.

### Ce qui change
Entropie Matérielle : Utilisation de cv2 (OpenCV) côté serveur pour déclencher la webcam et capturer une photo de la lampe à lave à la volée lors de la requête /seed.

Réseau Local : Le serveur FastAPI écoute sur 0.0.0.0 pour être accessible par n'importe quelle machine connectée au même Wi-Fi ou partage de connexion.

Décentralisation : Les scripts clients s'exécutent sur des ordinateurs distincts du serveur Debian hébergeant la webcam.

### Architecture
**Serveur central** (Machine Debian + Webcam) :
- Génération de l'entropie physique en direct.
- Registre public des clés RSA.
- Relais aveugle des messages chiffrés (WebSocket).

**Machines clientes** (Connectées au même réseau) :
- Création locale des clés RSA dérivées de la seed.
- Chiffrement/Déchiffrement hybride (RSA + AES-256-GCM).

### Utilisation : Procédure de test en réseau
**Étape 1** : Lancer le serveur (Sur le PC Debian avec la webcam)

Connectez le PC Debian au réseau (ex: partage de connexion).

Récupérez son adresse IP locale en tapant ``hostname -I`` ou ``ip a`` dans le terminal (par exemple : 10.112.177.253).

Lancez le serveur en l'exposant sur le réseau :


```bash
uvicorn src.server.server:app --host 0.0.0.0 --port 8000
```
$$***$$
**Étape 2** : Configurer les clients (Sur les autres PC)
Avant de lancer le script client, ouvrez le fichier src/client/client.py et modifiez la variable IP_SERV pour y mettre l'IP du serveur Debian obtenue à l'étape précédente :

```python
IP_SERV = "10.112.177.253" # Remplacer par l'IP du Debian
```
$$***$$

**Étape 3** : Lancer le Chat (2 terminaux clients)
Sur un ou deux PC différents connectés au même réseau :

Client B (Récepteur) : Lance `python -m src.client.client`, renseigne son pseudo et répond n (non initiateur).

Client A (Initiateur) : Lance `python -m src.client.client`, répond o (initiateur) et entre le pseudo de B.

La webcam du serveur prendra une photo en direct, l'entropie sera distribuée aux clients, la clé de session AES sera échangée en RSA, et le chat sécurisé commencera !

---

## Documentation

| Fichier | Contenu |
|---------|---------|
| [`docs/Cryptologie.md`](docs/Cryptologie.md) | Chiffrement : fonctionnement RSA, preuves mathématiques, padding OAEP, sécurité , utilisation AES-256-GCM|
| [`docs/Notes_V1.md`](docs/Notes_V1.md) | Contraintes et décisions de la V1 |
| [`docs/Notes_V2.md`](docs/Notes_V2.md) | Contraintes et décisions de la V2 |
| [`docs/Notes_V3.md`](docs/Notes_V3.md) | Contraintes et décisions de la V3 |
| [`docs/Notes_V4.md`](docs/Notes_V4.md) | Contraintes et décisions de la V4 |