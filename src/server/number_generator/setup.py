import numpy as np
import hashlib
import cv2


def images_to_bytes(frame: np.ndarray) -> bytes:
    """
    Prend une frame OpenCV (array numpy), la redimensionne en 50x50
    en niveaux de gris, et retourne son hash SHA-512 (64 octets).
    """
    image_grise = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    image_50x50 = cv2.resize(image_grise, (50, 50))
    raw_bytes   = image_50x50.flatten().tobytes()
    return hashlib.sha512(raw_bytes).digest()


"""
Diagramme pour visualiser la pipeline :

[matrice 50x50]
    ↓ flatten()
[2500 valeurs en ligne]
    ↓ tobytes()
[2500 octets bruts]
    ↓ sha256()
[32 octets] = la clé de chiffrement

"""