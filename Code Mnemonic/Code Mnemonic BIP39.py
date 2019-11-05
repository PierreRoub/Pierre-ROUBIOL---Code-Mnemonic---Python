#Pierre ROUBIOL

from random import *
import hashlib
from codecs import encode, decode
import binascii

# ETAPE 1, on génère un nombre de 128 bits

bits_binaire='0b'
for i in range(128):
    if random() <= 0.5:
        bits_binaire=bits_binaire+'0'            # génère un nombre de 128 bits
    else:
        bits_binaire=bits_binaire+'1'
        
bits=int(bits_binaire,2)                         # transforme le nombre de 128 bits en nombre decimal

bits_hexa = hex(bits).encode('utf-8')            # transforme le nombre decimal bits en nombre hexadecimal

# ETAPE 2, on génère une checksum en appliquant SHA256 au nombre précédent, et en prenant ici les 4 premiers bits de ce nombre

hash_bits_hexa=hashlib.sha256(bits_hexa)         # applique SHA256 au nombre hexadecimal

# ETAPE 3, on concatène cette checksum à la fin du nombre de 128 bits précédent

checksum=(bits_binaire+bin(int(hash_bits_hexa.hexdigest(),16))[2:6])[2:]    # on ajoute les 4 premier bits passés par le 
                                                                            # SHA256 à notre bits d'entropie
                                                                            
# ETAPE4 et 5, on sépare le nombre obtenu en 12 fois 11 bits, et chacun de ces 11 bits nous donnera 
#                                l'index d'un des douze mots du code mnemonic d'entropie 128 
                                                                        
liste=[]
liste_compte_rendu=[]
for i in range(0,132,11):                             # on sectionne nos 132 bits en 12 * 11 bits et 
     liste.append(int(checksum[i:i+11],2))              # on convertit chaque 11 bits en un nombre decimal
     liste_compte_rendu.append(checksum[i:i+11])   
       
mon_fichier = open("wordlist_eng.txt", "r")    # on importe les 2048 mots du BIP 39

wordlist=[]
for row in mon_fichier:                # dans les lignes suivantes on adapte la taille des mots déformé par les passages à la lignes
    wordlist.append(row)
for i in range(len(wordlist)-1):
    wordlist[i]=wordlist[i][0:len(wordlist[i])-1]

mnemonic_128=''
for i in range(12):
    mnemonic_128 = mnemonic_128 + wordlist[liste[i]]+ ' '     # on créé la séquence mnemonic
mnemonic_128 = mnemonic_128[0:len(mnemonic_128)-1]


# SEED
seed_bis = hashlib.pbkdf2_hmac('sha512', mnemonic_128.encode('utf-8'), ''.encode('utf-8'), 2048)    # on applique la fonction pbkdf2_hmac 

seed=''                                                                                        
for i in range(64):
    seed=seed+hex(seed_bis[i])[2:len(hex(seed_bis[i]))]                 # et on obtient le seed
    
print(" Pour simplifier l'exercice j'ai choisi de prendre une entropie de 128 (code en dur). J'ai suivi le livre Mastering "
      "Bitcoin essentiellement pour les 5 étapes détaillées. Les résultats obtenus à chaque étapes sont:" )
print("\nEtape 1: le nombre de 128 bits de cette compilation est:",bits_binaire )
print("\nEtape 2: les 4 premiers bits de ma checksum sont:",bin(int(hash_bits_hexa.hexdigest(),16))[2:6])
print("\nEtape 3: on concatène le nombre précédent et les 4 premiers bits de SHA256 du nombre:",checksum )
print("\nEtape 4: on sépare la checksum en 12 fois 11 bits et on obtient ces 12 nombres de 11 bits:", liste_compte_rendu )
print("\nEtape 5: chacun des nombres précédents correspondent à un nombre décimal qui est l'index de la wordlist dédié au BIP39:", liste)
print("\nCode Mnemonic obtenu: ", mnemonic_128 )
print("\n\n\nCependant je n'arrive pas à aller plus loin car selon le site 'https://iancoleman.io/bip39', mon code Mnemonic n'est pas "
      "bon et donc je n'arrive pas à obtenir une seed correct me permettant ensuite d'utiliser le BIP32!")