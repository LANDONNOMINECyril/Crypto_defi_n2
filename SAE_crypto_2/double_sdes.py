

from sdes import crypte_double_sdes, decrypte_double_sdes, cassage_astucieux, cassage_brutal
import matplotlib.pyplot as plt
import numpy as np


# In [2]:
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



# In [ ]:

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

