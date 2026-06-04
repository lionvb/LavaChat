"""
LavaChat — serveur Flask local (GUI)
Lancement : python -m src.gui.app
"""
import asyncio
import base64
import json
import threading
import os
import sqlite3
from datetime import datetime
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

# ── Configuration ─────────────────────────────────────────────────────────────

URL_CLOUDFLARE = "fitness-gabriel-currency-adventure.trycloudflare.com"
BASE_HTTP = f"https://{URL_CLOUDFLARE}"
BASE_WS   = f"wss://{URL_CLOUDFLARE}"

app  = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "templates"))
sock = Sock(app)


# ── Sessions multi-utilisateurs ───────────────────────────────────────────────

sessions: dict[str, dict] = {}

def get_session(username: str) -> dict:
    if username not in sessions:
        sessions[username] = {
            "username":      username,
            "cle_pub":       None,
            "cle_priv":      None,
            "cle_aes":       None,
            "destinataire":  None,
            "ws_cloudflare": None,
            "loop":          None,
            "inbox_chat":    None,
        }
    return sessions[username]

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

def maj_db(username: str, destinataire: str, last_connection: str = "date"):
    contacts_db = sqlite3.connect(f"{username}_contacts.db")
    cursor = contacts_db.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO contacts (username, last_connection) VALUES (?, ?)",
        (destinataire, last_connection)
    )
    contacts_db.commit()
    contacts_db.close()

def get_contacts_list(username: str) -> list[dict]:
    """Retourne [{"username": ..., "last_connection": ...}, ...] triés par date décroissante."""
    contacts_db = sqlite3.connect(f"{username}_contacts.db")
    cursor = contacts_db.cursor()
    cursor.execute("SELECT username, last_connection FROM contacts ORDER BY last_connection DESC")
    contacts = [{"username": row[0], "last_connection": row[1]} for row in cursor.fetchall()]
    contacts_db.close()
    return contacts

# ── Helpers HTTP vers serveur ─────────────────────────────────────────────────

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
    return render_template("index.html", ws_url="ws://localhost:5000")

def _authentifier(username: str, password: str, action: str) -> None:
    endpoint = "/register" if action == "register" else "/login"
    with httpx.Client() as c:
        r = c.post(f"{BASE_HTTP}{endpoint}", json={"username": username, "password": password})
        if r.status_code == 409:
            # Compte existant : vérifier le mot de passe via /login
            r_login = c.post(f"{BASE_HTTP}/login", json={"username": username, "password": password})
            r_login.raise_for_status()
        elif r.status_code not in (200, 201):
            r.raise_for_status()

@app.post("/connect")
def connect():
    username = request.json.get("username", "").strip()
    password = request.json.get("password", "").strip()
    action = request.json.get("action", "register") # Register par défault à voir pour un bouton de switch login/register
    if not username:
        return jsonify({"ok": False, "error": "Username vide."}), 400
    if not password:
        return jsonify({"ok": False, "error": "Mot de passe vide."}), 400

    try:
        _authentifier(username, password, action)
        init_db(username)
        seed = _obtenir_seed()
        nb1, nb2, _ = seed_vers_grands_entiers(seed)
        pub, priv = generer_cles_rsa(nb1, nb2)
        _publier_cle(username, pub)

        sess = get_session(username)
        sess["cle_pub"]  = pub
        sess["cle_priv"] = priv

        return jsonify({"ok": True})
    except httpx.HTTPStatusError as e:
        return jsonify({"ok": False, "error": f"Erreur d'authentification (Code {e.response.status_code})"}), 401
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.get("/contacts/<username>")
def contacts(username: str):
    if not username or username not in sessions:
        return jsonify({"ok": False, "error": "Session inconnue."}), 400
    try:
        return jsonify({"ok": True, "contacts": get_contacts_list(username)})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.post("/handshake/init")
def handshake_init():
    username     = request.json.get("username", "").strip()
    destinataire = request.json.get("destinataire", "").strip()
    if not username or not destinataire:
        return jsonify({"ok": False, "error": "Champs manquants."}), 400
    try:
        sess = get_session(username)

        seed = _obtenir_seed()
        _, _, nb3 = seed_vers_grands_entiers(seed)
        cle_aes = extraire_cle_aes(nb3)

        pub_dest     = _recuperer_cle(destinataire)
        aes_chiffree = chiffrer_RSA(cle_aes, pub_dest)
        payload_b64  = base64.b64encode(aes_chiffree).decode("ascii")

        asyncio.run_coroutine_threadsafe(
            sess["ws_cloudflare"].send(json.dumps({
                "type":    "aes_key",
                "to":      destinataire,
                "payload": payload_b64,
            })),
            sess["loop"],
        ).result(timeout=10)

        sess["cle_aes"]      = cle_aes
        sess["destinataire"] = destinataire
        maj_db(username=username,destinataire=destinataire,last_connection=datetime.now())

        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500




@app.post("/send")
def send_message():
    username = request.json.get("username", "").strip()
    text     = request.json.get("text", "")
    to       = request.json.get("to", "")
    if not username or not text or not to:
        return jsonify({"ok": False, "error": "Champs manquants."}), 400
    try:
        sess = get_session(username)
        if not sess.get("cle_aes"):
            return jsonify({"ok": False, "error": "peer_left"}), 409
        nonce, chiffre = chiffrement_AES(sess["cle_aes"], text)
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
            sess["ws_cloudflare"].send(json.dumps(msg)),
            sess["loop"],
        ).result(timeout=5)
        return jsonify({
            "ok":         True,
            "nonce":      base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "tag":        base64.b64encode(tag).decode("ascii"),
        })
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


# ── WebSocket bridge ──────────────────────────────────────────────────────────

@sock.route("/ws")
def ws_bridge(browser_ws):
    """
    Pont WebSocket : navigateur ←→ Flask (/ws) ←→ serveur WS
    Le username est passé en query string : ws://localhost:5000/ws?user=alice
    """
    username = request.args.get("user", "").strip()
    if not username or username not in sessions:
        browser_ws.send(json.dumps({"type": "error", "reason": "session_inconnue"}))
        return

    sess  = get_session(username)
    loop  = asyncio.new_event_loop()
    inbox = asyncio.Queue()   # messages Cloudflare → navigateur

    sess["loop"]       = loop
    sess["inbox_chat"] = asyncio.Queue()

    async def _run():
        url = f"{BASE_WS}/chat?user={username}"
        async with websockets.connect(url) as ws:
            sess["ws_cloudflare"] = ws

            async def _receive():
                async for raw in ws:
                    try:
                        msg = json.loads(raw)
                    except json.JSONDecodeError:
                        await inbox.put(raw)
                        continue

                    type_msg = msg.get("type")

                    if type_msg == "session_left":
                        sess["cle_aes"]      = None
                        sess["destinataire"] = None
                        await inbox.put(json.dumps({
                            "type": "session_left",
                            "from": msg.get("from"),
                        }))
                        continue

                    if type_msg == "aes_key":
                        # Toujours déchiffrer inline, que cle_aes soit None ou non.
                        try:
                            aes_chiffree = base64.b64decode(msg["payload"])
                            nouvelle_cle = dechiffrer_RSA(aes_chiffree, sess["cle_priv"])
                            if isinstance(nouvelle_cle, str):
                                nouvelle_cle = nouvelle_cle.encode("utf-8")
                            expediteur = msg.get("from")
                            sess["cle_aes"]      = nouvelle_cle
                            sess["destinataire"] = expediteur
                            maj_db(username=username, destinataire=expediteur,
                                   last_connection=str(datetime.now()))
                            await inbox.put(json.dumps({
                                "type": "session_renewed",
                                "from": expediteur,
                            }))
                        except Exception:
                            pass
                    else:
                        if type_msg == "message" and sess.get("cle_aes"):
                            try:
                                nonce      = base64.b64decode(msg["nonce"])
                                ciphertext = base64.b64decode(msg["ciphertext"])
                                tag        = base64.b64decode(msg["tag"])
                                plain = dechiffrement_AES(
                                    sess["cle_aes"], nonce, ciphertext + tag
                                )
                                msg["_plain"] = plain
                                raw = json.dumps(msg)
                            except Exception:
                                pass
                        await inbox.put(raw)

            asyncio.create_task(_receive())

            while True:
                try:
                    raw = await asyncio.wait_for(inbox.get(), timeout=0.1)
                    browser_ws.send(raw)
                except asyncio.TimeoutError:
                    pass
                except Exception:
                    break

    t = threading.Thread(target=loop.run_until_complete, args=(_run(),), daemon=True)
    t.start()

    # Reçoit les messages du navigateur → forward vers serveur
    while True:
        try:
            raw = browser_ws.receive()
            if raw is None:
                break
            if sess.get("ws_cloudflare"):
                asyncio.run_coroutine_threadsafe(
                    sess["ws_cloudflare"].send(raw),
                    loop,
                ).result(timeout=5)
        except Exception:
            break


@app.post("/session/reset")
def session_reset():
    username = request.json.get("username", "").strip()
    if not username or username not in sessions:
        return jsonify({"ok": False, "error": "Session inconnue."}), 400
    sess = sessions[username]

    # Prévenir l'interlocuteur avant de reset
    destinataire = sess.get("destinataire")
    if destinataire and sess.get("ws_cloudflare") and sess.get("loop"):
        try:
            asyncio.run_coroutine_threadsafe(
                sess["ws_cloudflare"].send(json.dumps({
                    "type": "session_left",
                    "to":   destinataire,
                })),
                sess["loop"],
            ).result(timeout=3)
        except Exception:
            pass

    sess["cle_aes"]      = None
    sess["destinataire"] = None
    return jsonify({"ok": True})


# ── Lancement ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import webbrowser
    PORT = 5000
    print(f"Serveur backend : {BASE_HTTP}")
    print(f"Interface accessible sur : http://localhost:{PORT}")
    webbrowser.open(f"http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)