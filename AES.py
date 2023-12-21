from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import time

def decrypte_aes(message_crypte, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decrypteur = cipher.decryptor()
    message_clair = decrypteur.update(message_crypte) + decrypteur.finalize()
    return message_clair

def encrypte_aes(message_clair, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    crypteur = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    message_clair = padder.update(message_clair) + padder.finalize()
    cipher_texte = crypteur.update(message_clair) + crypteur.finalize()
    return cipher_texte

cle = b'123456789abcdefghijklmnopqrstuvw'
message = b'Ce message est crypte avec AES'

# Chiffrement
start_c = time.time()
crypte = encrypte_aes(message, cle)
end_c = time.time() - start_c
print(f"Temps d'exécution du chiffrement AES : {end_c} secondes")

# Déchiffrement
start_d = time.time()
clair = decrypte_aes(crypte, cle)
end_d = time.time() - start_d
print(f"Temps d'exécution du déchiffrement AES : {end_d} secondes")
