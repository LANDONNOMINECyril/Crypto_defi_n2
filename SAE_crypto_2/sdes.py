import time
import constantes2 as c
from double_sdes import crypter, decrypt


def crypte_double_sdes(texte: str, cle1: int, cle2: int) -> str:
    """
    Fonction qui fait un double SDES sur le texte donné avec les clés données

    Args:
        texte (str): Le texte à crypter de n'importe quelle longueur
        cle1 (int): La première clé
        cle2 (int): La deuxième clé

    Returns:
        str: Le texte crypté
    """
    texte_crypte = ""
    for char in texte:
        lettre_int = ord(char)
        crypter_1 = crypter(cle1, lettre_int)
        crypter_2 = crypter(cle2, crypter_1)
        texte_crypte += chr(crypter_2)
    return texte_crypte


def decrypte_double_sdes(texte: str, cle1: int, cle2: int) -> str:
    """
    Fonction qui fait un double SDES sur le texte donné avec les clés données

    Args:
        texte (str): Le texte à crypter de n'importe quelle longueur
        cle1 (int): La première clé
        cle2 (int): La deuxième clé

    Returns:
        str: Le texte crypté
    """
    texte_decrypte = ""
    for char in texte:
        lettre_int = ord(char)
        decrypter_1 = decrypt(cle2, lettre_int)
        decrypter_2 = decrypt(cle1, decrypter_1)
        texte_decrypte += chr(decrypter_2)
    return texte_decrypte


def cassage_brutal(message_clair: str,
                   message_chiffre: str) -> tuple[int, int, int, float] | None:
    """
    Fonction qui casse le cryptage double SDES en testant toutes les clés possibles

    Args:
        message_clair (str): Le message clair
        message_chiffre (str): Le message chiffré

    Returns:
        tuple: La clé 1 et la clé 2, le nombre de tentatives et le temps de calcul
    """
    nombre_tentatives = 0
    debut = time.time()
    for cle1 in range(c.NOMBRE_CLE_POSSIBLE_SDES):
        for cle2 in range(c.NOMBRE_CLE_POSSIBLE_SDES):
            nombre_tentatives += 1
            if crypte_double_sdes(message_clair, cle1,
                                  cle2) == message_chiffre:
                temps = time.time() - debut
                temps = round(temps, 3)
                return (cle1, cle2, nombre_tentatives, temps)
    return None


def cassage_astucieux(
        message_clair: str,
        message_chiffre: str) -> tuple[int, int, int, float] | None:
    """
    Fonction qui casse le cryptage double SDES en utilisant
    les propriétés de la fonction de cryptage

    Args:
        message_clair (str): Le message clair
        message_chiffre (str): Le message chiffré

    Returns:
        tuple: La clé 1 et la clé 2, le nombre de tentatives et le temps de calcul
    """
    tableau = {}
    nombre_tentatives = 0
    debut = time.time()
    for cle1 in range(c.NOMBRE_CLE_POSSIBLE_SDES):
        message_crypte = crypte_double_sdes(message_clair, cle1, 0)
        tableau[message_crypte] = cle1
        nombre_tentatives += 1

    for cle2 in range(c.NOMBRE_CLE_POSSIBLE_SDES):
        nombre_tentatives += 1
        message_decrypte = decrypte_double_sdes(message_chiffre, 0, cle2)
        if message_decrypte in tableau:
            temps = time.time() - debut
            temps = round(temps, 3)
            return tableau[message_decrypte], cle2, nombre_tentatives, temps
    return None
