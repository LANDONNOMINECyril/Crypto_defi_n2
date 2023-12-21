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


"""
Module permettant de decrypter un trace reseau .cap
"""

from aes import decrypte_aes_cbc
from scapy.all import rdpcap, Raw, UDP
from steganographie import retrouve_cle
from cryptography.hazmat.primitives.padding import PKCS7


def analyse_trace() -> list[tuple[bytes, bytes]]:
    """
    Fonction permettant d'analyser le trace .cap

    Returns:
        list[tuple[bytes, bytes]]: La liste des données et des entêtes
    """
    packets = rdpcap('sujet/trace_sae.cap')
    liste: list[tuple[bytes, bytes]] = []
    for packet in packets:
        if packet.haslayer(UDP) and packet[UDP].dport == 9999:
            entete = packet[Raw].load[:16]
            data = packet[Raw].load[16:]
            liste.append((data, entete))
    return liste


def decrypte_message_alice_et_bob() -> list[str]:
    """
    Fonction qui decrypte les messages d'Alice et Bob dans le trace .cap
    """
    les_messages = analyse_trace()
    cle = retrouve_cle() * 4
    cle_int = int(cle, 2)  # Transforme la clé en int
    cle_bytes = cle_int.to_bytes(32,
                                 byteorder='big')  #Transforme la clé en bytes
    liste_messages: list[str] = []
    for message in les_messages:
        ciphertext = message[0]
        iv = message[1]
        ciphertext = PKCS7(128).padder().update(ciphertext)  # Ajout du padding
        liste_messages.append(decrypte_aes_cbc(iv, ciphertext, cle_bytes))
    return liste_messages

"""
Module contenant les constantes du deuxième défi
"""

NOMBRE_CLE_POSSIBLE_SDES = 256
NOMBRE_CLE_POSSIBLE_AES = 2**256
NOMBRE_OCTETS_CLE = 32
TEXTE_CRYPTER = 0

"""
Module qui contient les fonctions pour faire un double SDES
"""

import time
import constantes2 as c
from sdes import crypter, decrypt


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


from double_sdes import crypte_double_sdes, decrypte_double_sdes, cassage_astucieux, cassage_brutal
import matplotlib.pyplot as plt
import numpy as np


In [2]:
a = crypte_double_sdes("Je m'appelle Baptiste", 0b00000000, 0b11111111)
b = decrypte_double_sdes(a, 0b00000000, 0b11111111)

res_brutal = cassage_brutal("Je m'appelle Baptiste", a)
res_astucieux = cassage_astucieux("Je m'appelle Baptiste", a)

# Données
categories = ['Nombre tentatives', 'Temps mis']
tentatives = [res_astucieux[2], res_brutal[2]]
temps = [res_astucieux[3], res_brutal[3]]

# Création du graphique
fig, ax = plt.subplots()

ax.set_ylim(0, max(tentatives) + 1000)
ax.set_title("Comparaion cassage double SDES")
ax.set_ylabel("Nombre de tentatives")
ax.set_xticks(np.arange(len(categories)))
ax.set_xticklabels(categories)

# Création des barres
barres1 = ax.bar(np.arange(1) -0.2, tentatives[0], 0.4, label="Brutal", color="steelblue")
barres2 = ax.bar(np.arange(1) +0.2, tentatives[1], 0.4, label="Astucieux", color="orange")

ax.legend()
axe2 = ax.twinx()
axe2.set_ylabel("Temps mis (s)")
axe2.set_ylim(0, max(temps) + 2)
bar1 = axe2.bar(np.arange(1) + 1 -0.2, temps[0], 0.4, color="steelblue")
bar2 = axe2.bar(np.arange(1) + 1 +0.2, temps[1], 0.4, color="orange")

# Ajout des valeurs au dessus des barres
def ajouter_valeur(barres, axe):
    for barre in barres:
        hauteur = barre.get_height()
        axe.annotate('{}'.format(hauteur),
                    xy=(barre.get_x() + barre.get_width() / 2, hauteur),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom')

ajouter_valeur(barres1, ax)
ajouter_valeur(barres2, ax)
ajouter_valeur(bar1, axe2)
ajouter_valeur(bar2, axe2)

# Affichage du graphique
plt.show()



In [ ]:

"""
Module pour le SDES
"""

taille_cle = 10
sous_cle_taille = 8
longueur_donnee = 8
f_length = 4

# Tables for initial and final permutations (b1, b2, b3, ... b8)
initiale_table = (2, 6, 3, 1, 4, 8, 5, 7)
finale_table = (4, 1, 3, 5, 7, 2, 8, 6)

# Tables for subkey generation (k1, k2, k3, ... k10)
table_p10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
table_p8 = (6, 3, 7, 4, 8, 5, 10, 9)

# Tables for the fk function
table_ep = (4, 1, 2, 3, 2, 3, 4, 1)
table_50 = (1, 0, 3, 2, 3, 2, 1, 0, 0, 2, 1, 3, 3, 1, 3, 2)
table_s1 = (0, 1, 2, 3, 2, 0, 1, 3, 3, 0, 1, 0, 2, 1, 0, 3)
table_p4 = (2, 4, 3, 1)


def permuter(bit_entree: int, la_table_permutation: list):
    """
    Permute le byte d'entrée selon la table de permutation donnée

    Args:
        bit_entree (int): Le bit à permuter
        la_table_permutation (list): La table de permutation à utiliser
    """
    bit_sortie = 0
    for index, elem in enumerate(la_table_permutation):
        if index >= elem:
            bit_sortie |= (bit_entree & (128 >>
                                         (elem - 1))) >> (index - (elem - 1))
        else:
            bit_sortie |= (bit_entree & (128 >>
                                         (elem - 1))) << ((elem - 1) - index)
    return bit_sortie


def ip(bit_entree):
    """
    Effectue la permutation initiale des données

    Args:
        bit_entree (int): Le bit à permuter
    """
    return permuter(bit_entree, initiale_table)


def fp(bit_entree):
    """
    Effectue la permutation finale des données

    Args:
        bit_entree (int): Le bit à permuter
    """
    return permuter(bit_entree, finale_table)


def echange_nibble(bit_entree):
    """
    Échange les deux nibbles des données

    Args:
        bit_entree (int): Le bit à permuter
    """
    return (bit_entree << 4 | bit_entree >> 4) & 0xff


def generer_cles_sous_cles(cle):
    """
    Génère les deux sous-clés requises

    Args:
        cle (int): La clé à utiliser
    """

    def decalage_gauche(liste_bits: list):
        """
        Effectue un décalage circulaire à gauche sur les premiers et les deuxièmes cinq bits

        Args:
            liste_bits (list): La liste de bits à décaler
        """
        cle_decalee = [None] * taille_cle
        cle_decalee[0:9] = liste_bits[1:10]
        cle_decalee[4] = liste_bits[0]
        cle_decalee[9] = liste_bits[5]
        return cle_decalee

    liste_cles = [(cle & 1 << i) >> i for i in reversed(range(taille_cle))]
    perm_liste_cles = [None] * taille_cle
    for index, elem in enumerate(table_p10):
        perm_liste_cles[index] = liste_cles[elem - 1]
    cle_declage_1 = decalage_gauche(perm_liste_cles)
    cle_declage_2 = decalage_gauche(decalage_gauche(cle_declage_1))
    sous_cle1 = sous_cle2 = 0
    for index, elem in enumerate(table_p8):
        sous_cle1 += (128 >> index) * cle_declage_1[elem - 1]
        sous_cle2 += (128 >> index) * cle_declage_2[elem - 1]
    return (sous_cle1, sous_cle2)


def fonction_feistel(sous_cle, donnees):
    """
    Applique la fonction de Feistel sur les données avec la sous-clé donnée

    Args:
        sous_cle (int): La sous-clé à utiliser
        donnees (int): Les données à utiliser
    """

    def f(sous_cle, nibble_droit):
        aux = sous_cle ^ permuter(echange_nibble(nibble_droit), table_ep)
        index1 = ((aux & 0x80) >> 4) + ((aux & 0x40) >> 5) + \
                 ((aux & 0x20) >> 5) + ((aux & 0x10) >> 2)
        index2 = ((aux & 0x08) >> 0) + ((aux & 0x04) >> 1) + \
                 ((aux & 0x02) >> 1) + ((aux & 0x01) << 2)
        sortie_sbox = echange_nibble((table_50[index1] << 2) +
                                     table_s1[index2])
        return permuter(sortie_sbox, table_p4)

    nibble_gauche, nibble_droit = donnees & 0xf0, donnees & 0x0f
    return (nibble_gauche ^ f(sous_cle, nibble_droit)) | nibble_droit


def crypter(cle, le_texte):
    """
    Crypte le texte clair avec la clé donnée

    Args:
        cle (int): La clé à utiliser
        le_texte (str): Le texte clair à crypter
    """
    donnees = fonction_feistel(generer_cles_sous_cles(cle)[0], ip(le_texte))
    return fp(
        fonction_feistel(
            generer_cles_sous_cles(cle)[1], echange_nibble(donnees)))


def decrypt(key, ciphertext):
    """Decrypt ciphertext with given key"""
    donnees = fonction_feistel(generer_cles_sous_cles(key)[1], ip(ciphertext))
    return fp(
        fonction_feistel(
            generer_cles_sous_cles(key)[0], echange_nibble(donnees)))

"""
Module pour la stéganographie sur les images
"""

from PIL import Image


def meme_image(nom_image1: str, nom_image2: str) -> bool:
    """
    Fonction qui compare deux images pixel par pixel et qui renvoie True si elles sont identiques

    Args:
        nom_image1 (str): Le nom de la première image
        nom_image2 (str): Le nom de la deuxième image

    Returns:
        bool: True si les images sont identiques, False sinon
    """
    image = Image.open(nom_image1)
    image2 = Image.open(nom_image2)
    nombre_colonne = image.size[0]
    nombre_ligne = image.size[1]
    for ind in range(nombre_ligne):
        for ind2 in range(nombre_colonne):
            pixel_en_cours_img_1 = image.getpixel((ind2, ind))
            pixel_en_cours_img_2 = image2.getpixel((ind2, ind))
            if pixel_en_cours_img_1 != pixel_en_cours_img_2:
                return False
    return True


def retrouve_cle() -> str:
    """
    Fonction qui retrouve la clé de cryptage AES cachée dans l'image

    Returns:
        str: La clé de cryptage AES
    """
    image2 = Image.open("sujet/rossignol2.bmp")
    nombre_colonne, nombre_ligne = image2.size[0], image2.size[1]
    cle = ""
    cpt = 0
    for ind in range(nombre_ligne):
        for ind2 in range(nombre_colonne):
            if cpt < 64:
                pixel_en_cours_img_2 = image2.getpixel((ind2, ind))
                cle += bin(pixel_en_cours_img_2)[-1]
                cpt += 1
    return cle


