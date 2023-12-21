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
