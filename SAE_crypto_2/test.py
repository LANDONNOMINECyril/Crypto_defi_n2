#!/usr/bin/python3
#
# Author: Joao H de A Franco (jhafranco@acm.org)
#
# Description: Simplified DES implementation in Python 3
#
# Date: 2012-02-10
#
# License: Attribution-NonCommercial-ShareAlike 3.0 Unported
#          (CC BY-NC-SA 3.0)
#===========================================================
from sys import exit
from time import time
 
taille_de_la_cle = 10
SubKeyLength = 8
DataLength = 8
FLength = 4
 
# Tables for initial and final permutations (b1, b2, b3, ... b8)
table_de_permutation_initiale = (2, 6, 3, 1, 4, 8, 5, 7)
table_de_permutation_finale = (4, 1, 3, 5, 7, 2, 8, 6)
 
# Tables for sous_cle generation (k1, k2, k3, ... k10)
table_de_generation_de_sous_cle_10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
table_de_generation_de_sous_cle_8 = (6, 3, 7, 4, 8, 5, 10, 9)
 
# Tables for the feistel_function function
EPtable = (4, 1, 2, 3, 2, 3, 4, 1)
S0table = (1, 0, 3, 2, 3, 2, 1, 0, 0, 2, 1, 3, 3, 1, 3, 2)
S1table = (0, 1, 2, 3, 2, 0, 1, 3, 3, 0, 1, 0, 2, 1, 0, 3)
P4table = (2, 4, 3, 1)
 
def permutation_byte_avec_permut_table(byte_donne, table_de_permutation):
    """Permute input byte according to permutation table"""
    byte_permute = 0
    for index, elem in enumerate(table_de_permutation):
        if index >= elem:
            byte_permute |= (byte_donne & (128 >> (elem - 1))) >> (index - (elem - 1))
        else:
            byte_permute |= (byte_donne & (128 >> (elem - 1))) << ((elem - 1) - index)
    #print("le byte : ",byte_donne,"|permute devient :",byte_permute)
    return byte_permute
 
def premiere_permutation_de_la_data(byte_donne):
    """Perform the initial permutation on donnee"""
    return permutation_byte_avec_permut_table(byte_donne, table_de_permutation_initiale)
 
def derniere_permutation_de_la_data(byte_donne):
    """Perform the final permutation on donnee"""
    return permutation_byte_avec_permut_table(byte_donne, table_de_permutation_finale)
 
def permute_les_deux_nibbles_de_la_data(byte_donne):
    """Swap the two nibbles of donnee"""
    return (byte_donne << 4 | byte_donne >> 4) & 0xff
 
def generation_des_deux_sous_cle(cle):
    """Generate the two required subkeys"""
    def leftShift(keyBitList):
        """Perform a circular left shift on the first and second five bits"""
        shiftedKey = [None] * taille_de_la_cle
        shiftedKey[0:9] = keyBitList[1:10]
        shiftedKey[4] = keyBitList[0]
        shiftedKey[9] = keyBitList[5]
        return shiftedKey
 
    # Converts input cle (integer) into a list of binary digits
    keyList = [(cle & 1 << i) >> i for i in reversed(range(taille_de_la_cle))]
    liste_cle_de_permutation = [None] * taille_de_la_cle
    for index, elem in enumerate(table_de_generation_de_sous_cle_10):
        liste_cle_de_permutation[index] = keyList[elem - 1]
    sous_cle_shift_une_fois = leftShift(liste_cle_de_permutation)
    sous_cle_shift_trois_fois = leftShift(leftShift(sous_cle_shift_une_fois))
    sous_cle_1 = sous_cle_2 = 0
    for index, elem in enumerate(table_de_generation_de_sous_cle_8):
        sous_cle_1 += (128 >> index) * sous_cle_shift_une_fois[elem - 1]
        sous_cle_2 += (128 >> index) * sous_cle_shift_trois_fois[elem - 1]
    #print("les deux sous_cle sont: ",sous_cle_1, sous_cle_2)
    return (sous_cle_1, sous_cle_2)
 
def feistel_function(sous_cle, data_rentre):
    """Apply Feistel function on donnee with given sous_cle"""
    def F(sKey, rightNibble):
        aux = sKey ^ permutation_byte_avec_permut_table(permute_les_deux_nibbles_de_la_data(rightNibble), EPtable)
        index1 = ((aux & 0x80) >> 4) + ((aux & 0x40) >> 5) + \
                 ((aux & 0x20) >> 5) + ((aux & 0x10) >> 2)
        index2 = ((aux & 0x08) >> 0) + ((aux & 0x04) >> 1) + \
                 ((aux & 0x02) >> 1) + ((aux & 0x01) << 2)
        sboxOutputs = permute_les_deux_nibbles_de_la_data((S0table[index1] << 2) + S1table[index2])
        return permutation_byte_avec_permut_table(sboxOutputs, P4table)
 
    leftNibble, rightNibble = data_rentre & 0xf0, data_rentre & 0x0f
    #print("la donnee après feistel function",(leftNibble ^ F(sous_cle, rightNibble)) | rightNibble)
    return (leftNibble ^ F(sous_cle, rightNibble)) | rightNibble
 
def encryptage(cle, texte_clair):
    """encryptage texte_clair with given cle"""
    #print("cle :", cle, "|texte_clair :",texte_clair)
    donnee = feistel_function(generation_des_deux_sous_cle(cle)[0], premiere_permutation_de_la_data(texte_clair))
    message_crypte = derniere_permutation_de_la_data(feistel_function(generation_des_deux_sous_cle(cle)[1], permute_les_deux_nibbles_de_la_data(donnee)))
    return message_crypte
 
def decryptage(cle, texte_crypte):
    """decryptage texte_crypte with given cle"""
    #print("cle :", cle, "|texte_crypte :",texte_crypte)
    donnee = feistel_function(generation_des_deux_sous_cle(cle)[1], premiere_permutation_de_la_data(texte_crypte))
    message_decrypte = derniere_permutation_de_la_data(feistel_function(generation_des_deux_sous_cle(cle)[0], permute_les_deux_nibbles_de_la_data(donnee)))  
    #print("message_decrypte :", message_decrypte)
    return message_decrypte
 
# if __name__ == '__main__':
    # Test vectors described in "Simplified DES (SDES)"
    # (http://www2.kinneret.ac.il/mjmay/ise328/328-Assignment1-SDES.pdf)
 
    # try:
    #     assert encryptage(0b0000000000, 0b10101010) == 0b00010001
    # except AssertionError:
    #     print("Error on encryptage:")
    #     print("Output: ", encryptage(0b0000000000, 0b10101010), "Expected: ", 0b00010001)
    #     exit(1)
    # try:
    #     assert encryptage(0b1110001110, 0b10101010) == 0b11001010
    # except AssertionError:
    #     print("Error on encryptage:")
    #     print("Output: ", encryptage(0b1110001110, 0b10101010), "Expected: ", 0b11001010)
    #     exit(1)
    # try:
    #     assert encryptage(0b1110001110, 0b01010101) == 0b01110000
    # except AssertionError:
    #     print("Error on encryptage:")
    #     print("Output: ", encryptage(0b1110001110, 0b01010101), "Expected: ", 0b01110000)
    #     exit(1)
    # try:
    #     assert encryptage(0b1111111111, 0b10101010) == 0b00000100
    # except AssertionError:
    #     print("Error on encryptage:")
    #     print("Output: ", encryptage(0b1111111111, 0b10101010), "Expected: ", 0b00000100)
    #     exit(1)
 
    # t1 = time()
    # for i in range(1000):
    #     encryptage(0b1110001110, 0b10101010)
    # t2 = time()
    # print("Elapsed time for 1,000 encryptions: {:0.3f}s".format(t2 - t1))
    # exit()
    
def creation_cles(j):
    return [i for i in range(2**j)]

def cryptage2SDES(texte_clair,cle,cle2):
    encrypte1 = encryptage(cle, texte_clair)
    encrypte2 = encryptage(cle2, encrypte1)
    return encrypte2

def int_from_bytes(input_string):
    liste = []
    for char in input_string:
        liste.append(int.from_bytes(bytes(char,'utf-8'),'big'))
    return liste

def bytes_to_str(input_list):
    result = ''
    for num in input_list:
        try:
            # Essayez de décoder l'octet en tant que caractère UTF-8
            char = num.to_bytes((num.bit_length() + 7) // 8, 'big').decode('utf-8')
            # Si le décodage réussit, ajoutez le caractère au résultat
            result += char
        except UnicodeDecodeError:
            # Si le décodage échoue, ajoutez l'entier au résultat
            result += str(num) + ' '
    return result.strip()

def cryptage_simple_mot(mot,cle1):
    liste= []
    mot_chiffre = int_from_bytes(mot)
    for chiffre in mot_chiffre:
        liste.append(encryptage(cle1,chiffre))
    return liste
    
def decryptage_simple_mot(texte_chiffre,cle1):
    liste= []
    for chiffre in texte_chiffre:
        liste.append(decryptage(cle1,chiffre))
    return liste

def cryptage_mot(mot, cle1, cle2):
    liste = []
    mot_chiffre = int_from_bytes(mot)
    for chiffre in mot_chiffre:
        liste.append(cryptage2SDES(chiffre,cle1,cle2))
    return liste

def cassage2SDESastucieux(message_crypte, message_clair):
    cle1 = creation_cles(10)
    dico = dict()
    for premiere_cle in cle1:
        t1 = tuple(cryptage_simple_mot(message_clair,premiere_cle))
        dico[t1] = premiere_cle
        if tuple(decryptage_simple_mot(message_crypte,premiere_cle)) in dico.keys():
            return (dico[tuple(decryptage_simple_mot(message_crypte,premiere_cle))], premiere_cle)
    return None

'''fonctionne pas :'''


'''fonctionne : '''
mottest = "LETTRE I USBEK À SON AMI RUSTAN. À Ispahan. Nous n’avons séjourné qu’un jour à Com. Lorsque nous eûmes fait nos dévotions sur le tombeau de la vierge qui a mis au monde douze prophètes, nous nous remîmes en chemin, et hier, vingt-cinquième jour de notre départ d’Ispahan, nous arrivâmes à Tauris. Rica et moi sommes peut-être les premiers parmi les Persans que l’envie de savoir ait fait sortir de leur pays, et qui aient renoncé aux douceurs d’une vie tranquille pour aller chercher laborieusement la sagesse. Nous sommes nés dans un royaume florissant ; mais nous n’avons pas cru que ses bornes fussent celles de nos connoissances, et que la lumière orientale dût seule nous éclairer. Mande-moi ce que l’on dit de notre voyage ; ne me flatte point : je ne compte pas sur un grand nombre d’approbateurs. Adresse ta lettre à Erzeron, où je séjournerai quelque temps. Adieu, mon cher Rustan. Sois assuré qu’en quelque lieu du monde où je sois, tu as un ami fidèle. De Tauris, le 15 de la lune de Saphar, 1711."
print(bytes_to_str(int_from_bytes(mottest)))
print(cryptage_simple_mot(mottest,0b1100001110))
mott = cryptage_simple_mot(mottest,0b1100001110)
print(decryptage_simple_mot(mott,0b1100001110))
messagecrypte = cryptage_mot(mottest,0b1100001110, 0b1110001110)
print(messagecrypte)
print("suite")
print(cassage2SDESastucieux(messagecrypte,mottest))
print("résultat attendu :",0b1100001110, 0b1110001110)