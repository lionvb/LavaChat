import asyncio
import json
import base64

import httpx
import websockets

import sqlite3

"""python -m src.client.client"""

from src.encrypt_decrypt.encrypt_decrypt import (
    chiffrer_RSA,
    dechiffrer_RSA,
    chiffrement_AES,
    dechiffrement_AES,
)
from src.encrypt_decrypt.key_generator import (
    extraire_cle_aes,
    generer_cles_rsa,
    seed_vers_grands_entiers,
)
#Partage Victor : 10.211.31.253
#Partage Louis  : 10.112.177.253
URL_CLOUDFLARE = "especially-gulf-improving-brussels.trycloudflare.com"
BASE_HTTP = f"https://{URL_CLOUDFLARE}"
BASE_WS = f"wss://{URL_CLOUDFLARE}" 

# INITIALISATION DE LA BASE DE DONNÉES SQL DES CONTACTS
def init_db(username:str):
    contacts_db = sqlite3.connect(f"{username}_contacts.db")
    cursor = contacts_db.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            last_connection TEXT NOT NULL
        )
    """)
    contacts_db.commit()
    contacts_db.close()

def maj_db(username:str,destinataire:str ,last_connection:str="date"):
    try:
        contacts_db = sqlite3.connect(f"{username}_contacts.db")
        cursor = contacts_db.cursor()
        cursor.execute(
            "INSERT INTO contacts (username, last_connection) VALUES (?, ?)", 
            (destinataire, last_connection)
        )
        contacts_db.commit()
    except sqlite3.IntegrityError:
        print("Problème dans la mise à jour de la liste des contacts")
        print(username,destinataire)
    finally:
        contacts_db.close()

def set_username():
    username=input("\nQuelle est votre username ? : ")
    return username

def enregistrer(username: str,password: str) -> None:
    """Inscrit un nouvel utilisateur ou connecte un utilisateur existant."""
    with httpx.Client() as client:
        # 1. On tente d'abord de l'inscrire
        r = client.post(f"{BASE_HTTP}/register", json={"username": username,"password":password})
        if r.status_code == 409:
            # 2. Le compte existe déjà ! On bascule sur la route de connexion
            r_login = client.post(f"{BASE_HTTP}/login", json={"username": username,"password":password})
            if r_login.status_code == 401:
                print("\n[ERREUR] Mot de passe incorrect pour cet utilisateur.")
                exit(1)
            r_login.raise_for_status()

        elif r.status_code != 201:
            r.raise_for_status()
        init_db(username)


def obtenir_seed() -> str:
    """Récupère une seed d'entropie de 64 octets en hexadécimal via GET /seed."""
    r = httpx.get(f"{BASE_HTTP}/seed", timeout=30)
    r.raise_for_status()
    return r.json()["seed"]


def publier_cle(username: str, cle_publique: dict) -> None:
    """Publie la clé publique RSA d'un utilisateur via POST /publickey."""
    payload = {
        "username": username,
        "n": cle_publique["n"],
        "e": cle_publique["e"],
    }
    with httpx.Client() as client:
        r = client.post(f"{BASE_HTTP}/publickey", json=payload)
        if r.status_code != 201:
            r.raise_for_status()


def recuperer_cle(destinataire: str) -> dict:
    """Récupère la clé publique RSA d'un autre utilisateur via GET /publickey/{username}."""
    r = httpx.get(f"{BASE_HTTP}/publickey/{destinataire}", timeout=5.0)
    r.raise_for_status()
    data = r.json()
    return {"n": data["n"], "e": data["e"]}

def initialiser_session(username: str,password: str) -> tuple[dict, dict]:
    """
    Phase d'initialisation locale commune à tous les clients :
    inscription, obtention d'une seed, dérivation de la paire RSA,
    publication de la clé publique sur le serveur.

    Retourne (cle_publique, cle_privee), chacune au format
    {"n": int, "e": int} ou {"n": int, "d": int}.
    """
    enregistrer(username,password)
    seed_bytes = bytes.fromhex(obtenir_seed())
    nb1, nb2, _ = seed_vers_grands_entiers(seed_bytes)
    cle_publique, cle_privee = generer_cles_rsa(nb1, nb2)
    publier_cle(username, cle_publique)
    return cle_publique, cle_privee


def generer_cle_aes_session() -> bytes:
    """
    Génère une clé AES-256 de session, dérivée d'une seed serveur.

    À n'appeler que côté initiateur de la WebSocket. Le récepteur ne
    génère pas de clé locale : il récupère celle de l'initiateur via
    le message aes_key au début de la session.
    """
    seed_bytes = bytes.fromhex(obtenir_seed())
    _, _, nb3 = seed_vers_grands_entiers(seed_bytes)
    return extraire_cle_aes(nb3)

async def ouvrir_websocket(username: str) -> None:
    """
    Ouvre la WebSocket de chat et la maintient ouverte jusqu'à fermeture
    (côté serveur via close-frame, ou côté utilisateur via Ctrl+C).

    Sous-étape 2 : on se contente de la connexion. Aucun message n'est
    envoyé ; les messages reçus sont loggés mais pas traités.
    """
    url = f"{BASE_WS}/chat?user={username}"
    print(f"\nConnexion à {url} ...")
    async with websockets.connect(url) as ws:
        print(f"Connecté en tant que {username}. Ctrl+C pour quitter.")
        async for message in ws:
            print(f"[reçu] {message}")
    # Une fois le `async with` sorti, la WS est fermée des deux côtés.
    print(f"Connexion fermée — code={ws.close_code} reason={ws.close_reason!r}")

async def envoyer_cle_aes(ws, destinataire: str, cle_aes: bytes) -> None:
    """
    Côté initiateur : récupère la clé publique RSA du destinataire,
    chiffre la clé AES de session avec, encode le résultat en base64,
    et envoie le tout sur la WS via un message :
        {"type": "aes_key", "to": <destinataire>, "payload": <base64>}
    """
    pub_dest = recuperer_cle(destinataire)
    aes_chiffree = chiffrer_RSA(cle_aes, pub_dest)
    payload_b64 = base64.b64encode(aes_chiffree).decode("ascii")

    message = {
        "type": "aes_key",
        "to": destinataire,
        "payload": payload_b64,
    }
    await ws.send(json.dumps(message))
    print(f"Clé AES envoyée (chiffrée RSA) à {destinataire}.")

async def main_client() -> None:
    """Orchestration interactive du client."""
    username = input("\nUsername : ").strip()
    if not username:
        print("Username vide, abandon.")
        return
    password = input("\nPassword (min 8 caracters): ").strip()
    if not password:
        print("Password vide, abandon.")
        return
    pub, priv = initialiser_session(username, password)
    print(f"\nSession initialisée pour {username}.")

    # Boucle principale — on revient ici après chaque session de chat
    while True:
        print("\n" + "─" * 40)
        print("  Nouvelle session")
        print("─" * 40)
        reponse = input("Êtes-vous l'initiateur de la session ? (o/n) ou 'quitter' pour sortir : ").strip().lower()

        if reponse in ("quitter", "q"):
            print("Au revoir.")
            break

        est_initiateur = reponse.startswith("o")

        destinataire = None
        cle_aes = None
        if est_initiateur:
            destinataire = input("Username du destinataire : ").strip()
            cle_aes = generer_cle_aes_session()
            print(f"\nClé AES de session générée. Aperçu : {cle_aes[:8].hex()}... (32 octets)")

        url = f"{BASE_WS}/chat?user={username}"
        print(f"\nConnexion à {url} ...")
        try:
            async with websockets.connect(url) as ws:
                print(f"Connecté en tant que {username}.")

                if est_initiateur:
                    await envoyer_cle_aes(ws, destinataire, cle_aes)
                    maj_db(username,destinataire)
                else:
                    cle_aes, destinataire = await attendre_handshake_aes(ws, priv)
                    maj_db(username,destinataire)
                    print(
                        f"Clé AES reçue de {destinataire}."
                        f"\nAperçu : {cle_aes[:8].hex()}... ({len(cle_aes)} octets)"
                    )

                print(f"\nChat en cours avec {destinataire}. Tape '/quitter' pour revenir au menu.\n")
                await asyncio.gather(
                    boucle_envoyer(ws, cle_aes, destinataire),
                    boucle_recevoir(ws, cle_aes),
                )
        except websockets.exceptions.ConnectionClosed as e:
            print(f"\nSession fermée — code={e.code} reason={e.reason!r}")

        print("\nSession terminée.")

def traiter_aes_key(message: dict, cle_privee: dict) -> bytes:
    """
    Côté récepteur : décode la charge utile base64 d'un message `aes_key`
    et la déchiffre avec la clé privée RSA pour récupérer la clé AES en clair.
    """
    aes_chiffree = base64.b64decode(message["payload"])
    cle_aes = dechiffrer_RSA(aes_chiffree, cle_privee)
    # `dechiffrer_RSA` renvoie un str si les octets déchiffrés forment un
    # UTF-8 valide, sinon des bytes. Pour 32 octets aléatoires c'est rare
    # mais possible — on normalise systématiquement en bytes.
    if isinstance(cle_aes, str):
        cle_aes = cle_aes.encode("utf-8")
    return cle_aes

async def attendre_handshake_aes(ws, cle_privee: dict) -> tuple[bytes, str]:
    """
    Côté récepteur : lit la WS jusqu'à recevoir un message `aes_key`,
    le déchiffre, et retourne (cle_aes, destinataire) où destinataire
    est l'expéditeur du handshake (notre interlocuteur).
    """
    async for raw in ws:
        try:
            message = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if message.get("type") == "aes_key":
            cle_aes = traiter_aes_key(message, cle_privee)
            return cle_aes, message.get("from")
        elif message.get("type") == "error":
            print(f"[erreur serveur] {message.get('reason')}")
    raise RuntimeError("WebSocket fermée avant le handshake AES.")


async def boucle_envoyer(ws, cle_aes: bytes, destinataire: str) -> None:
    """Lit le clavier, chiffre AES-GCM, envoie sur la WS. '/quitter' ferme la session."""
    while True:
        try:
            texte = await asyncio.to_thread(input, "")
        except EOFError:
            return
        if not texte:
            continue

        if texte.strip().lower() == "/quitter":
            print("\nFermeture de la session en cours...")
            await ws.close()
            return

        nonce, chiffre = chiffrement_AES(cle_aes, texte)
        # AES-GCM : les 16 derniers octets de la sortie sont le tag d'authentification.
        ciphertext = chiffre[:-16]
        tag = chiffre[-16:]

        message = {
            "type": "message",
            "to": destinataire,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
        }
        await ws.send(json.dumps(message))


async def boucle_recevoir(ws, cle_aes: bytes) -> None:
    """Reçoit les messages, les déchiffre AES-GCM et les affiche."""
    async for raw in ws:
        try:
            message = json.loads(raw)
        except json.JSONDecodeError:
            print(f"[non-JSON] {raw}")
            continue

        type_msg = message.get("type")
        if type_msg == "message":
            try:
                nonce = base64.b64decode(message["nonce"])
                ciphertext = base64.b64decode(message["ciphertext"])
                tag = base64.b64decode(message["tag"])
                chiffre = ciphertext + tag
                texte = dechiffrement_AES(cle_aes, nonce, chiffre)
                print(f"\n[{message.get('from')}] {texte}")
            except Exception as exc:
                print(f"[erreur déchiffrement] {type(exc).__name__}: {exc}")
        elif type_msg == "error":
            print(f"[erreur serveur] {message.get('reason')}")
        else:
            print(f"[type inconnu] {message}")

if __name__ == "__main__":

    try:
        asyncio.run(main_client())
    except KeyboardInterrupt:
        print("\nFermeture demandée.")