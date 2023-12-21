from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import time

def decrypte_des(message_crypte, cle):
    cipher = DES.new(cle, DES.MODE_ECB)
    message_clair = cipher.decrypt(message_crypte)
    return unpad(message_clair, DES.block_size)

def encrypte_des(message_clair, cle):
    cipher = DES.new(cle, DES.MODE_ECB)
    message_clair = pad(message_clair, DES.block_size)
    return cipher.encrypt(message_clair)

# Exemple d'utilisation
cle = b'12345678'
message = b'Ce message est crypte avec DES'

# Chiffrement
start_c = time.time()
crypte = encrypte_des(message, cle)
end_c = time.time() - start_c
print(f"Temps d'exécution du chiffrement DES : {end_c} secondes")

# Déchiffrement
start_d = time.time()
clair = decrypte_des(crypte, cle)
end_d = time.time() - start_d
print(f"Temps d'exécution du déchiffrement DES : {end_d} secondes")