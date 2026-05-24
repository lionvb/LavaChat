"""
LavaChat — serveur Flask local (GUI)
Lancement : python -m src.gui.app
"""
import asyncio
import base64
import json
import threading

from flask import Flask, render_template, request, jsonify
from flask_sock import Sock
import httpx
import websockets

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

# ── Configuration ────────────────────────────────────────────────────────────

URL_CLOUDFLARE = "extension-continuity-informative-shore.trycloudflare.com"
BASE_HTTP = f"https://{URL_CLOUDFLARE}"
BASE_WS   = f"wss://{URL_CLOUDFLARE}"

app  = Flask(__name__)
sock = Sock(app)

# ── État de session (par simplicité : une session globale) ───────────────────

session = {
    "username":    None,
    "cle_pub":     None,
    "cle_priv":    None,
    "cle_aes":     None,
    "destinataire": None,
    "ws_cloudflare": None,   # websockets.WebSocketClientProtocol
    "loop":        None,     # event loop asyncio dédié
}


# ── Helpers HTTP vers Cloudflare ─────────────────────────────────────────────

def _enregistrer(username: str) -> None:
    with httpx.Client() as c:
        r = c.post(f"{BASE_HTTP}/register", json={"username": username})
        if r.status_code not in (201, 409):
            r.raise_for_status()


def _obtenir_seed() -> bytes:
    r = httpx.get(f"{BASE_HTTP}/seed", timeout=30)
    r.raise_for_status()
    return bytes.fromhex(r.json()["seed"])


def _publier_cle(username: str, cle_pub: dict) -> None:
    with httpx.Client() as c:
        r = c.post(f"{BASE_HTTP}/publickey",
                   json={"username": username, "n": cle_pub["n"], "e": cle_pub["e"]})
        if r.status_code != 201:
            r.raise_for_status()


def _recuperer_cle(username: str) -> dict:
    r = httpx.get(f"{BASE_HTTP}/publickey/{username}", timeout=5)
    r.raise_for_status()
    d = r.json()
    return {"n": d["n"], "e": d["e"]}


# ── Routes HTTP ───────────────────────────────────────────────────────────────

@app.get("/")
def index():
    return render_template("index.html")


@app.post("/connect")
def connect():
    """Écran 1 → inscription + génération des clés RSA."""
    username = request.json.get("username", "").strip()
    if not username:
        return jsonify({"ok": False, "error": "Username vide."}), 400
    try:
        _enregistrer(username)
        seed = _obtenir_seed()
        nb1, nb2, _ = seed_vers_grands_entiers(seed)
        pub, priv = generer_cles_rsa(nb1, nb2)
        _publier_cle(username, pub)

        session["username"]  = username
        session["cle_pub"]   = pub
        session["cle_priv"]  = priv

        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.post("/handshake/init")
def handshake_init():
    """Écran 2 initiateur → génère clé AES + l'envoie via WS Cloudflare."""
    destinataire = request.json.get("destinataire", "").strip()
    if not destinataire:
        return jsonify({"ok": False, "error": "Destinataire vide."}), 400
    try:
        seed = _obtenir_seed()
        _, _, nb3 = seed_vers_grands_entiers(seed)
        cle_aes = extraire_cle_aes(nb3)

        pub_dest    = _recuperer_cle(destinataire)
        aes_chiffree = chiffrer_RSA(cle_aes, pub_dest)
        payload_b64  = base64.b64encode(aes_chiffree).decode("ascii")

        # Envoi via l'event loop dédié
        asyncio.run_coroutine_threadsafe(
            session["ws_cloudflare"].send(json.dumps({
                "type": "aes_key",
                "to":   destinataire,
                "payload": payload_b64,
            })),
            session["loop"],
        ).result(timeout=10)

        session["cle_aes"]      = cle_aes
        session["destinataire"] = destinataire

        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.post("/handshake/wait")
def handshake_wait():
    """Écran 2 récepteur → attend le message aes_key (bloquant, max 60 s)."""
    try:
        future = asyncio.run_coroutine_threadsafe(
            _attendre_aes_key(), session["loop"]
        )
        cle_aes, expediteur = future.result(timeout=60)
        session["cle_aes"]      = cle_aes
        session["destinataire"] = expediteur
        return jsonify({"ok": True, "destinataire": expediteur})
    except TimeoutError:
        return jsonify({"ok": False, "error": "Délai dépassé (60 s)."}), 408
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


async def _attendre_aes_key() -> tuple[bytes, str]:
    ws = session["ws_cloudflare"]
    async for raw in ws:
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if msg.get("type") == "aes_key":
            aes_chiffree = base64.b64decode(msg["payload"])
            cle_aes = dechiffrer_RSA(aes_chiffree, session["cle_priv"])
            if isinstance(cle_aes, str):
                cle_aes = cle_aes.encode("utf-8")
            return cle_aes, msg.get("from")
    raise RuntimeError("WS fermée avant handshake AES.")


# ── WebSocket navigateur ↔ Cloudflare ────────────────────────────────────────

@app.post("/send")
def send_message():
    """Chiffre un message AES-GCM et l'envoie via la WS Cloudflare."""
    text = request.json.get("text", "")
    to   = request.json.get("to", "")
    if not text or not to:
        return jsonify({"ok": False, "error": "Champs manquants."}), 400
    try:
        nonce, chiffre = chiffrement_AES(session["cle_aes"], text)
        ciphertext = chiffre[:-16]
        tag        = chiffre[-16:]
        msg = {
            "type":       "message",
            "to":         to,
            "nonce":      base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "tag":        base64.b64encode(tag).decode("ascii"),
        }
        asyncio.run_coroutine_threadsafe(
            session["ws_cloudflare"].send(json.dumps(msg)),
            session["loop"],
        ).result(timeout=5)
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@sock.route("/ws")
def ws_bridge(browser_ws):
    """
    Pont WebSocket :
      navigateur  ←→  Flask (/ws)  ←→  Cloudflare WS
    Ouvre la connexion Cloudflare dans un thread asyncio dédié,
    puis fait le relais dans les deux sens.
    """
    username = session.get("username")
    if not username:
        browser_ws.send(json.dumps({"type": "error", "reason": "non_connecté"}))
        return

    loop = asyncio.new_event_loop()
    session["loop"] = loop

    # File de messages entrants (Cloudflare → navigateur)
    inbox = asyncio.Queue()

    async def _run():
        url = f"{BASE_WS}/chat?user={username}"
        async with websockets.connect(url) as ws:
            session["ws_cloudflare"] = ws

            async def _receive():
                async for raw in ws:
                    # Déchiffrement AES-GCM des messages entrants
                    try:
                        msg = json.loads(raw)
                        if msg.get("type") == "message" and session.get("cle_aes"):
                            nonce      = base64.b64decode(msg["nonce"])
                            ciphertext = base64.b64decode(msg["ciphertext"])
                            tag        = base64.b64decode(msg["tag"])
                            plain = dechiffrement_AES(
                                session["cle_aes"], nonce, ciphertext + tag
                            )
                            msg["_plain"] = plain
                            raw = json.dumps(msg)
                    except Exception:
                        pass
                    await inbox.put(raw)

            asyncio.create_task(_receive())

            # Boucle principale : dépile l'inbox et forward au navigateur
            while True:
                try:
                    raw = await asyncio.wait_for(inbox.get(), timeout=0.1)
                    browser_ws.send(raw)
                except asyncio.TimeoutError:
                    pass
                except Exception:
                    break

    # Lance la boucle asyncio dans un thread séparé
    t = threading.Thread(target=loop.run_until_complete, args=(_run(),), daemon=True)
    t.start()

    # Reçoit les messages du navigateur et les forward à Cloudflare
    while True:
        try:
            raw = browser_ws.receive()
            if raw is None:
                break
            asyncio.run_coroutine_threadsafe(
                session["ws_cloudflare"].send(raw),
                loop,
            ).result(timeout=5)
        except Exception:
            break


# ── Lancement ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import webbrowser
    webbrowser.open("http://localhost:5000")
    app.run(port=5000, debug=False)
