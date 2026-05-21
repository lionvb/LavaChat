"""
Génération des nombres premiers et des clés RSA.
"""
import math
import hashlib

# TEST DE PRIMALITÉ — Miller-Rabin
def est_premier(n: int) -> bool:
    """
    Test de primalité déterministe Miller-Rabin.
    Utilise des témoins fixes qui couvrent sans faux positif tous les entiers jusqu'à 3.3 × 10²⁴.
    """
    if n < 2:
        return False

    petits_premiers = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]

    # Cas trivial : n est l'un des petits témoins
    if n in petits_premiers:
        return True

    # Divisibilité rapide par les petits premiers
    if any(n % p == 0 for p in petits_premiers):
        return False

    # Décomposer n - 1 = 2^r × d (avec d impair)
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Test de Miller-Rabin avec chaque témoin
    for a in petits_premiers:
        if a >= n:
            continue

        x = pow(a, d, n)            # a^d mod n

        if x in (1, n - 1):
            continue                # témoin "passé", continuer

        for _ in range(r - 1):
            x = pow(x, 2, n)       # x² mod n
            if x == n - 1:
                break
        else:
            return False            # n est n'est pas premier avec certitude

    return True                     # n est (très probablement) premier

# RECHERCHE DU PROCHAIN NOMBRE PREMIER

def prochain_premier(n: int) -> int:
    """
    Transforme un nombre aléatoire quelconque (issu de la source
    d'entropie externe) en un nombre premier utilisable pour RSA.
    """
    candidat = abs(n) | 1       # valeur absolue et forcer impair (avec | opérateur OU binaire)
    while not est_premier(candidat):
        candidat += 2
    return candidat

# GÉNÉRATION DE LA PAIRE DE CLÉS RSA

def generer_cles_rsa(nb_alea_1: int,nb_alea_2: int) -> tuple:
    """
    Génère une paire de clés RSA à partir de deux grands entiers aléatoires.

    Paramètres :
    nb_alea_1 : grand entier aléatoire
    nb_alea_2 : grand entier aléatoire différent du premier

    Retourne
    cle_publique : dict { 'n': int, 'e': int }
    cle_privee   : dict { 'n': int, 'd': int }

    Schéma RSA : 
    n    = p × q             module public  (connu de tous)
    φ(n) = (p−1)(q−1)        indicatrice d'Euler  (secret)
    e    = 65537             exposant public  (standard)
    d    = e⁻¹ mod φ(n)      exposant privé  (secret absolu)
    """
    # Étape 1 : Construire deux grands nombres premiers à partir des aléas
    p = prochain_premier(nb_alea_1)
    q = prochain_premier(nb_alea_2)

    # p et q doivent être différents (sinon n = p² est factorisable facilement)
    if p == q:
        q = prochain_premier(q + 2)

    # Étape 2 : Module RSA et indicatrice d'Euler
    n     = p * q
    phi_n = (p - 1) * (q - 1)

    # Étape 3 : Exposant public e = 65537 (= 2¹⁶ + 1 : petit, premier, standard)
    e = 65537
    if math.gcd(e, phi_n) != 1:
        raise ValueError("e=65537 n'est pas copremier avec φ(n).Changez les nombres aléatoires sources.")

    # Étape 4 : Exposant privé d = e⁻¹ mod φ(n) 
    d = pow(e, -1, phi_n)

    cle_publique = {"n": n, "e": e}
    cle_privee   = {"n": n, "d": d}
    return cle_publique, cle_privee

def seed_vers_grands_entiers(seed: bytes) -> tuple:
    """
    Dérive deux grands entiers de 512 bits depuis un hash (seed).
    Principe — dérivation par étiquette  :

    Chaque appel produit 64 octets. On répète et concatène jusqu'à
    atteindre TARGET_BITS bits, puis on convertit en entier.
 
    Pourquoi des étiquettes différentes ("RSA_P" / "RSA_Q") ?
    → Garantit que nombre_1 ≠ nombre_2 même si la seed est courte,
      car SHA-512("RSA_P" + seed) et SHA-512("RSA_Q" + seed) sont
      cryptographiquement indépendants.
 
    Paramètres
    ----------
    seed : bytes — hash issu de la source d'entropie du collègue
                   (typiquement 64 octets / SHA-512, mais taille libre)
 
    Retourne
    --------
    (nombre_1, nombre_2) : deux entiers de TARGET_BITS bits
    """
    TARGET_BITS  = 512          # taille souhaitée en bits pour p et q
    TARGET_BYTES = TARGET_BITS // 8   # = 64 octets
 
    if not isinstance(seed, bytes) or len(seed) == 0:
        raise ValueError("seed doit être un bytes non vide.")
 
    def deriver(etiquette: bytes) -> int:
        """Produit un entier de TARGET_BITS bits depuis seed + étiquette."""
        resultat = b""
        compteur = 0
        while len(resultat) < TARGET_BYTES:
            bloc = hashlib.sha512(
                seed + etiquette + compteur.to_bytes(4, "big")
            ).digest()                      # 64 octets
            resultat += bloc
            compteur += 1
        # Limiter à exactement TARGET_BYTES octets
        resultat = resultat[:TARGET_BYTES]
        # Forcer le bit de poids fort à 1 → garantir exactement TARGET_BITS bits
        resultat = bytes([resultat[0] | 0x80]) + resultat[1:]
        return int.from_bytes(resultat, "big")
 
    nombre_1 = deriver(b"RSA_P")
    nombre_2 = deriver(b"RSA_Q")
    nombre_3 = deriver(b"AES_KEY")
 
    return nombre_1, nombre_2,nombre_3

def extraire_cle_aes(nombre_3: int) -> bytes:
    """
    Convertit l'entier dérivé de 512 bits 'nombre_3' en une clé AES-256 valide de 32 octets.
    """
    # 1. Converti le grand entier de 512 bit en une séquence de 64 bytes
    cle_brute = nombre_3.to_bytes(64, byteorder="big")
    
    # 2. Garde seulement les 32 premiers bits nécessaires pour l'AES-256
    cle_aes = cle_brute[:32]
    
    return cle_aes