"""
Module pour l'AES
"""
from cryptography.fernet import Fernet
import constantes2 as c
import base64
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def crypte_aes(texte: str, cle: int) -> str:
    """
    Fonction qui crypte un texte avec l'algorithme AES avec la bibliothèque cryptography

    Args:
        texte (str): Le texte à crypter
        cle (int): La clé de cryptage

    Returns:
        str: Le texte crypté
    """
    cle_bytes = cle.to_bytes(c.NOMBRE_OCTETS_CLE, 'big')
    cle_encoded = base64.urlsafe_b64encode(cle_bytes)
    f = Fernet(cle_encoded)
    texte_crypte = f.encrypt(texte.encode())
    return texte_crypte.hex()


def decrypte_aes(texte: str, cle: int) -> str:
    """
    Fonction qui décrypte un texte avec l'algorithme AES avec la bibliothèque cryptography

    Args:
        texte (str): Le texte à décrypter
        cle (int): La clé de décryptage

    Returns:
        str: Le texte décrypté
    """
    try:
        cle_bytes = cle.to_bytes(c.NOMBRE_OCTETS_CLE, 'big')
        cle_encoded = base64.urlsafe_b64encode(cle_bytes)
        f = Fernet(cle_encoded)
        texte_decrypte = f.decrypt(bytes.fromhex(texte))
        return texte_decrypte.decode()
    except Exception as e:
        raise Exception('Une erreur est survenue lors du décryptage') from e


def crypte_aes_cbc(iv: bytes, plaintext: bytes, key: bytes) -> bytes:
    """
    Fonction qui crypte un texte avec l'algorithme AES en mode CBC avec la bibliothèque pycryptodome

    Args:
        iv (bytes): Le vecteur d'initialisation
        plaintext (bytes): Le texte à crypter
        key (bytes): La clé de cryptage

    Returns:
        bytes: Le texte crypté
    """
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(plaintext)
        return ciphertext
    except Exception as e:
        raise Exception('Une erreur est survenue lors du cryptage') from e


def decrypte_aes_cbc(iv: bytes, ciphertext: bytes, key: bytes) -> str:
    """
    Fonction qui décrypte un texte avec l'algorithme AES en mode CBC avec
    la bibliothèque pycryptodome

    Args:
        iv (bytes): Le vecteur d'initialisation
        ciphertext (bytes): Le texte chiffré
        key (bytes): La clé de décryptage

    Returns:
        str: Le texte décrypté
    """
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode('utf-8')
    except Exception as e:
        raise Exception('Une erreur est survenue lors du décryptage') from e


def cassage_brutal(message_clair: str,
                   message_chiffre: str) -> tuple[int, int, float] | None:
    """
    Fonction qui casse le cryptage AES en testant toutes les clés possibles

    Args:
        message_clair (str): Le message clair
        message_chiffre (str): Le message chiffré

    Returns:
        tuple: La clé, le nombre de tentatives et le temps de calcul
    """
    debut = time.time()
    tentatives = 0
    for cle in range(c.NOMBRE_CLE_POSSIBLE_AES):
        try:
            message_decrypte = decrypte_aes(message_chiffre, cle)
        except Exception:
            message_decrypte = None
        tentatives += 1
        if message_decrypte == message_clair:
            fin = time.time()
            return (cle, tentatives, fin - debut)
    return None