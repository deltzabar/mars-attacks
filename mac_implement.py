##TODO##
# implement TMAC as a test
# find concrete meaning for OMAC
# if i can, implement OMAC
# else, read the stuff about PMAC and jump there
# try to think about the abstract attacks that would be possible if neither works

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def setup():
    global iv
    iv = os.urandom(16)

def blockEncrypt(k1, m):
    cipher = Cipher(algorithms.AES(k1), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(m) + encryptor.finalize()

def blockDecrypt(k1, c):
    cipher = Cipher(algorithms.AES(k1), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(c) + decryptor.finalize()

def peel(m, n):
    if len(m) > n:
        return m[:n], m[n:]
    else:
        return m, []
    
def omacKeyGen(k1):
    # encrypt n 0s using k1
    k0 = blockEncrypt(k1, b"0000000000000000000000000000000000000000000000000000000000000000") #this is using n = 64
    k2 = u(k0)
    k3 = u(k2) #thus k3 = Lu2
    return k1, k2, k3 

def u(L):
    # if most significant b = 0, then simply perform <<1
    C = 0x000000000000001b
    hexL = L.hex()
    binL = bin(int(hexL, base=16)).removeprefix('0b')
    print(binL)
    if binL[1] == 0:
        intL = int.from_bytes(L, byteorder='big')
        shiftL = intL << 1
        return shiftL.to_bytes(2, byteorder='big')
    else:
        intL = int.from_bytes(L, byteorder='big')
        shiftL = (intL << 1) ^ C
        return shiftL.to_bytes(2, byteorder='big')
    # else, perform <<1
    # then xor with constant
    



def main():
    setup()
    key = os.urandom(32)
    #ctxt = blockEncrypt(key, b"1111111111111111")
    #print(ctxt)
    #output = blockDecrypt(key, ctxt)
    #print(output)
    message = "12345678901234567890"
    first, second = peel(message, 16)
    print(first + " " + second)
    toEnc = str.encode(first)
    #print(blockDecrypt(key, blockEncrypt(key, toEnc)))
    omacKeyGen(key)



main()


