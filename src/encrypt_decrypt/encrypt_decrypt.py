"""
Chiffrement RSA avec padding OAEP.

Le padding OAEP (Optimal Asymmetric Encryption Padding) est utilisé pour protéger contre les attaques classiques sur le RSA brut
"""

import hashlib
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# FONCTION INTERNE — Mask Generation Function (MGF1 / SHA-256)
def _mgf(graine: bytes, longueur: int) -> bytes:
    """
    Génère un masque pseudo-aléatoire de `longueur` octets à partir d'une `graine`, en utilisant SHA-256.
    """
    masque = b""
    for i in range((longueur + 31) // 32):
        masque += hashlib.sha256(graine + i.to_bytes(4, "big")).digest()
    return masque[:longueur]

# FONCTION PUBLIQUE — Chiffrement

def chiffrer_RSA(message: str, cle_publique: dict) -> bytes:
    n, e  = cle_publique["n"], cle_publique["e"]
    k     = (n.bit_length() + 7) // 8
    if type(message) == bytes:
        msg_b = message
    else:
        msg_b = message.encode("utf-8")
    capacite_max = k - 37

    if capacite_max <= 0:
        raise ValueError(f"Clé trop courte : {n.bit_length()} bits. Minimum requis : ~300 bits.")

    # Découpage en blocs
    blocs = [msg_b[i:i + capacite_max] for i in range(0, len(msg_b), capacite_max)]

    blocs_chiffres = []
    for bloc_msg in blocs:
        L   = len(bloc_msg)
        sel = os.urandom(32)

        msg_masque = bytes(a ^ b for a, b in zip(bloc_msg, _mgf(sel, L)))
        sel_masque = bytes(a ^ b for a, b in zip(sel, _mgf(msg_masque, 32)))

        bloc = b"\x00" + sel_masque + L.to_bytes(4, "big") + msg_masque
        bloc = bloc.ljust(k, b"\x00")

        m = int.from_bytes(bloc, "big")
        c = pow(m, e, n)
        blocs_chiffres.append(c.to_bytes(k, "big"))

    # Préfixe : nombre de blocs (4 bytes) pour que le déchiffrement sache combien itérer
    return len(blocs_chiffres).to_bytes(4, "big") + b"".join(blocs_chiffres)

def dechiffrer_RSA(message_chiffre: bytes, cle_privee: dict) -> str:
    n, d = cle_privee["n"], cle_privee["d"]
    k    = (n.bit_length() + 7) // 8

    # Lire le préfixe : nombre de blocs
    nb_blocs = int.from_bytes(message_chiffre[:4], "big")
    blocs_chiffres = [
        message_chiffre[4 + i * k : 4 + (i + 1) * k]
        for i in range(nb_blocs)
    ]

    blocs_dechiffres = []
    for bloc_chiffre in blocs_chiffres:

        # Validation
        if len(bloc_chiffre) != k:
            raise ValueError(f"Bloc invalide : {len(bloc_chiffre)} octets reçus, {k} attendus.")
        c = int.from_bytes(bloc_chiffre, "big")
        if c >= n:
            raise ValueError("Bloc invalide : valeur hors du domaine RSA (c >= n).")

        # RSA inverse : m = c^d mod n
        m    = pow(c, d, n)
        bloc = m.to_bytes(k, "big")

        # Retrait du padding OAEP
        sel_masque = bloc[1:33]
        L          = int.from_bytes(bloc[33:37], "big")
        capacite_max = k - 37
        if L > capacite_max:
            raise ValueError(f"Longueur récupérée ({L}) incohérente (max : {capacite_max}).")

        msg_masque = bloc[37 : 37 + L]
        sel        = bytes(a ^ b for a, b in zip(sel_masque, _mgf(msg_masque, 32)))
        msg_b      = bytes(a ^ b for a, b in zip(msg_masque, _mgf(sel, L)))
        blocs_dechiffres.append(msg_b)

    # Reconstruction du message complet
    try:
        return b"".join(blocs_dechiffres).decode("utf-8")
    except UnicodeDecodeError:
        return b"".join(blocs_dechiffres)  
  
def chiffrement_AES(cle_aes: bytes, message_clair: str) -> tuple:
    """
    Chiffre un message en clair en utilisant AES-256-GCM.
    Génère automatiquement un nonce unique de 12 octets pour ce chiffrement spécifique.
    
    Arguments:
        cle_aes (bytes): La clé AES de 32 octets dérivée de la seed maître.
        message_clair (str): Le message en texte clair à chiffrer.
        
    Retourne:
        tuple: (nonce (bytes), texte_chiffre_avec_tag (bytes))
    """
    # 1. Génération d'un Nonce unique et sécurisé de 96 bits (12 octets) pour ce message
    nonce = os.urandom(12)
    
    # 2. Conversion du message texte en octets (bytes)
    message_bytes = message_clair.encode('utf-8')
    
    # 3. Initialisation de la machine AES-GCM et chiffrement
    aesgcm = AESGCM(cle_aes)
    
    # La fonction encrypt retourne le texte chiffré avec le tag d'authentification de 16 octets à la fin
    texte_chiffre_avec_tag = aesgcm.encrypt(nonce, message_bytes, associated_data=None)
    
    # Nous devons retourner le nonce avec le texte chiffré, car le destinataire en a besoin pour déchiffrer !
    return nonce, texte_chiffre_avec_tag

def dechiffrement_AES(cle_aes: bytes, nonce: bytes, texte_chiffre_avec_tag: bytes) -> str:
    """
    Déchiffre un texte chiffré AES-256-GCM et vérifie son intégrité.
    
    Arguments:
        cle_aes (bytes): La clé AES de 32 octets dérivée de la seed maître.
        nonce (bytes): Le nonce de 12 octets utilisé lors du chiffrement.
        texte_chiffre_avec_tag (bytes): Les données chiffrées incluant le tag d'authentification.
        
    Retourne:
        str: Le message déchiffré en texte clair.
        
    Lève:
        ValueError: Si le tag d'authentification est invalide (données altérées ou corrompues).
    """
    aesgcm = AESGCM(cle_aes)
    
    try:
        # La méthode decrypt extrait et vérifie automatiquement le tag d'authentification
        octets_dechiffres = aesgcm.decrypt(nonce, texte_chiffre_avec_tag, associated_data=None)
        
        return octets_dechiffres.decode('utf-8')
        
    except InvalidTag:
        # Cela empêche l'application de renvoyer un message altéré par un attaquant ou un problème réseau
        print("[CRITIQUE] Échec de l'authentification ! Le message a été altéré ou corrompu.")
        raise ValueError("Échec du contrôle d'intégrité : Tag d'authentification invalide.")