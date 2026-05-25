"""
Serveur FastAPI — V3 du projet lava_entropy.

Étape 1 : squelette minimal.
Permet uniquement de valider que la stack ASGI tourne.

Lancement en localhost : >> uvicorn src.server.server:app --reload
Lancemnet en réseau local : >> uvicorn src.server.server:app --host 0.0.0.0 --port 8000
"""
import json

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field

import cv2
from src.server.number_generator.setup import images_to_bytes

import time
import subprocess

async def envoyer_erreur(ws: WebSocket, raison: str, to: str | None = None) -> None:
    """Envoie un message d'erreur structuré à un client WS."""
    payload = {"type": "error", "reason": raison}
    if to is not None:
        payload["to"] = to
    await ws.send_text(json.dumps(payload))

app = FastAPI(title="lava_entropy — serveur V3")

# Ensemble des usernames enregistrés via POST /register.
utilisateurs: set[str] = set()

# Clés publiques RSA des utilisateurs
cles_publiques: dict[str, dict] = {}

# Connexions WebSocket actives : 
connexions: dict[str, WebSocket] = {}

# File d'attente des messages aes_key pour les destinataires non encore connectés
# { username_destinataire: [message_json, ...] }
aes_key_en_attente: dict[str, list] = {}

# ---------------------------------------------------------------------------
# Schémas Pydantic
# ---------------------------------------------------------------------------
# Pydantic valide automatiquement les corps de requête/réponse et alimente
# la doc Swagger générée par FastAPI sur /docs.

class DemandeInscription(BaseModel):
    """Corps de requête de POST /register."""
    username: str = Field(min_length=1, max_length=32)


class ReponseInscription(BaseModel):
    """Réponse de POST /register."""
    username: str
    status: str


class ReponseSeed(BaseModel):
    """Réponse de GET /seed : seed d'entropie en hexadécimal."""
    seed: str

class DemandeCleePublique(BaseModel):
    """Corps de requête de POST /publickey."""
    username: str = Field(min_length=1, max_length=32)
    n: int = Field(gt=0)
    e: int = Field(gt=0)


class ReponseCleePublique(BaseModel):
    """Réponse de POST /publickey."""
    username: str
    status: str

class CleePublique(BaseModel):
    """Réponse de GET /publickey/{username} : clé publique RSA d'un utilisateur."""
    username: str
    n: int
    e: int

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
def racine():
    """Endpoint de santé : vérifie simplement que le serveur répond."""
    return {"status": "ok"}


@app.post(
    "/register",
    response_model=ReponseInscription,
    status_code=status.HTTP_201_CREATED,
)
def inscrire(demande: DemandeInscription) -> ReponseInscription:
    """
    Enregistre un nouvel utilisateur.

    - 201 Created : username libre, inscription effectuée.
    - 409 Conflict : username déjà pris.
    - 422 Unprocessable Entity : validation Pydantic échouée (auto par FastAPI).
    """
    if demande.username in utilisateurs:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{demande.username}' déjà utilisé.",
        )

    utilisateurs.add(demande.username)
    return ReponseInscription(username=demande.username, status="registered")

def capturer_photo_webcam() -> bytes:
    camera = cv2.VideoCapture(0)
    if not camera.isOpened():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Webcam indisponible.",
        )
    try:
        #On force la haute résolution
        camera.set(cv2.CAP_PROP_FRAME_WIDTH, 1920)
        camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 1080)

        # On met le serveur en pause pendant 2 secondes. 
        # La caméra est allumée et son capteur s'ajuste à la lumière réelle.
        print("Calibrage du capteur de la webcam...")
        time.sleep(2.0)

        # Pendant ces 2 secondes, Linux a stocké les toutes premières images 
        # (les petites et noires) dans la mémoire tampon (buffer) de la caméra.
        # On lit et on jette rapidement les 10 premières images pour vider ce buffer.
        for _ in range(10):
            camera.grab()  # grab() est comme read(), mais ultra-rapide car il ne décode pas l'image

        ok, frame = camera.read()
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Impossible de lire un frame depuis la webcam.",
            )
            
        cv2.imwrite("test_entropie.jpg", frame)
        print("Capture réussie ! Photo sauvegardée.")

        # On crée un script Python d'une ligne qui lit l'image, l'affiche,
        # attend 3000 millisecondes (3 secondes), puis s'arrête tout seul.
        code_affichage = (
            "import cv2; "
            "img = cv2.imread('test_entropie.jpg'); "
            "cv2.imshow('Validation Entropie (fermeture auto)', img); "
            "cv2.waitKey(3000)"
        )
        
        try:
            # On lance ce mini-script en tâche de fond
            subprocess.Popen(["python3", "-c", code_affichage])
        except Exception as e:
            print(f"Impossible de lancer l'affichage : {e}")

        return images_to_bytes(frame)
    finally:
        camera.release()       
        
@app.get("/seed", response_model=ReponseSeed)
def obtenir_seed() -> ReponseSeed:
    """
    Capture une photo via la webcam du serveur, l'utilise comme
    source d'entropie et renvoie une seed en hexadécimal.
    """
    seed = capturer_photo_webcam().hex()
    return ReponseSeed(seed=seed)

@app.post(
    "/publickey",
    response_model=ReponseCleePublique,
    status_code=status.HTTP_201_CREATED,
)
def publier_cle_publique(demande: DemandeCleePublique) -> ReponseCleePublique:
    """
    Publie la clé publique RSA d'un utilisateur déjà enregistré.

    - 201 Created : clé publiée (écrase la précédente si elle existait,
      pour permettre la rotation à chaque nouvelle session).
    - 404 Not Found : username inconnu (l'utilisateur doit d'abord
      passer par POST /register).
    - 422 Unprocessable Entity : validation Pydantic échouée
      (auto par FastAPI, par exemple si n ou e sont absents ou ≤ 0).
    """
    if demande.username not in utilisateurs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Username '{demande.username}' non enregistré.",
        )

    cles_publiques[demande.username] = {"n": demande.n, "e": demande.e}
    return ReponseCleePublique(username=demande.username, status="key_published")

@app.get(
    "/publickey/{username}",
    response_model=CleePublique,
)
def recuperer_cle_publique(username: str) -> CleePublique:
    """
    Récupère la clé publique RSA d'un utilisateur.

    - 200 OK : la clé est renvoyée.
    - 404 Not Found : aucune clé publiée pour ce username
      (soit il n'existe pas, soit il ne s'est pas encore enregistré
      côté /publickey).
    """
    if username not in cles_publiques:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Aucune clé publique trouvée pour '{username}'.",
        )

    cle = cles_publiques[username]
    return CleePublique(username=username, n=cle["n"], e=cle["e"])

@app.websocket("/chat")
async def chat(websocket: WebSocket):
    """
    WebSocket du chat chiffré (étape 4b — connexion + routage).

    Le client doit fournir son username via la query string :
        ws://localhost:8000/chat?user=alice

    Format des messages JSON acceptés (client -> serveur) :
    - {"type": "aes_key", "to": "<username>", "payload": "<b64>"}
        Handshake initial : clé AES de session chiffrée RSA pour le destinataire.
    - {"type": "message", "to": "<username>", "nonce": "<b64>", "ciphertext": "<b64>", "tag": "<b64>"}
        Message chiffré AES-GCM.

    Le serveur enrichit le message d'un champ `from` (et retire `to`)
    avant de le transmettre au destinataire. Si le destinataire est offline
    ou si le message est mal formé, un message d'erreur est renvoyé à
    l'expéditeur sans rompre la connexion.
    """
    username = websocket.query_params.get("user")
    await websocket.accept()

    if not username:
        await websocket.close(code=1008, reason="username_manquant")
        return
    if username not in utilisateurs:
        await websocket.close(code=1008, reason="username_inconnu")
        return
    if username in connexions:
        await websocket.close(code=1008, reason="deja_connecte")
        return

    connexions[username] = websocket

    # Livraison des messages aes_key reçus pendant que le client était offline
    for msg_en_attente in aes_key_en_attente.pop(username, []):
        await websocket.send_text(json.dumps(msg_en_attente))
        
    try:
        while True:
            raw = await websocket.receive_text()

            # Parsing JSON
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                await envoyer_erreur(websocket, "json_invalide")
                continue
            if not isinstance(message, dict):
                await envoyer_erreur(websocket, "format_invalide")
                continue

            # Validation : type connu
            type_msg = message.get("type")
            if type_msg not in ("aes_key", "message"):
                await envoyer_erreur(websocket, "type_inconnu")
                continue

            # Validation : destinataire renseigné
            destinataire = message.get("to")
            if not isinstance(destinataire, str) or not destinataire:
                await envoyer_erreur(websocket, "to_manquant")
                continue

            # Routage
            message_relaye = {k: v for k, v in message.items() if k != "to"}
            message_relaye["from"] = username

            ws_dest = connexions.get(destinataire)
            if ws_dest is not None:
                # Destinataire connecté : envoi immédiat
                await ws_dest.send_text(json.dumps(message_relaye))
            else:
                if type_msg == "aes_key":
                    # Destinataire offline : on met en file d'attente
                    aes_key_en_attente.setdefault(destinataire, []).append(message_relaye)
                else:
                    # Messages normaux non délivrables : on notifie l'expéditeur
                    await envoyer_erreur(websocket, "recipient_offline", to=destinataire)

    except WebSocketDisconnect:
        pass
    finally:
        connexions.pop(username, None)