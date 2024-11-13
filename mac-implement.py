import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def setup():
    global iv
    iv: bytes = os.urandom(16)

def blockEncrypt(k1: bytes, m: bytes):
    cipher = Cipher(algorithms.AES(k1), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(m) + encryptor.finalize()

def blockDecrypt(k1: bytes, c: bytes):
    cipher = Cipher(algorithms.AES(k1), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(c) + decryptor.finalize()

def peel(m: str, n: int):
    if len(m) > n:
        return m[:n], m[n:]
    else:
        return m, []
    
def omacKeyGen(k1: bytes):
    # encrypt n 0s using k1
    k0 = blockEncrypt(k1, b'\0' * 16) #this is using n =128 thus 16 bytes
    k2: int = u(k0)
    ##TODO: will break on second round bc needs bytes##
    k3: int = u(k2) #thus k3 = Lu2
    return k1, k2, k3 

def u(L: bytes):
    # if most significant b = 0, then simply perform <<1
    C = 0x00000000000000000000000000000087  #this is the constant for n=128
    hexL = L.hex() #converts to hex, for visibility & to then move to binary
    print("hexL: "+hexL)
    binL = bin(int(hexL, base=16)).removeprefix('0b') #converts to binary to allow bitwise comparison
    intL: int = int.from_bytes(L, byteorder='big') #convert to int for bitwise operations
    print("binL: "+binL)
    if binL[1] == 0:
        print("starts with 0")
        shiftL: int = intL << 1
        return shiftL
     # else, perform <<1
    else:
        print("starts with 1")
        shiftL: int = (intL << 1) ^ C
        #print(hex(shiftL)) 
        return shiftL
   
    # then xor with constant

def OMAC(k1: bytes, k2: int, k3: int, m: str):
    ##TODO: Making assumption here that message is a STRING##
    block, rest = peel(m)
    #check if last block
    if rest != []:
        #create first Enc block
        toEnc: bytes = str.encode(block)
        enc1: bytes = blockEncrypt(k1, toEnc)
        intEnc = int.from_bytes(enc1, byteorder='big')
        while rest != []: #loop while there are still more block to come
            block, rest = peel(rest)
            if rest == []: #if nothing left, do lastblock procedures
                return lastblock(k1, k2, k3, block, enc1)
            else:
                intBlock = int.from_bytes(block, byteorder='big')
                xor: int = intEnc ^ intBlock
                enc1 = blockEncrypt(k1, xor)
                intEnc = int.from_bytes(enc1, byteorder='big')
                #perform encryption
    #if yes
    else:
        return lastblock(k1, k2, k3, block, [])


def lastblock(k1: bytes, k2: int, k3: int, m: str, enc1: bytes):
    ##TODO:Check types match expected##
    if enc1 == []:
        if len(m) == 16:
            last: int = k2 ^ m
            return blockEncrypt(k1, last)
        else:
            ##apply padding
            last: int = k3 ^ m
            return blockEncrypt(k1, last)
    else:
        if len(m) == 16:
            last: int = m ^ enc1 ^ k2
            return blockEncrypt(k1, last)
        else:
            ##run padding
            last: int = m ^ enc1 ^ k3
            return blockEncrypt(k2, last)
    
def OMACverif():
    print("placeholder!")

def OMACattack1():
    print("placeholder!")

def main():
    setup()
    key = os.urandom(32)
    print("key: "+key.hex())
    #ctxt = blockEncrypt(key, b"1111111111111111")
    #print(ctxt)
    #output = blockDecrypt(key, ctxt)
    #print(output)
    #message = "12345678901234567890"
    #first, second = peel(message, 16)
    #toEnc = str.encode(first)
    #print(blockDecrypt(key, blockEncrypt(key, toEnc)))
    k1, k2, k3 = omacKeyGen(key)



main()

##k2 and k3 DONT HAVE TO BE BYTES !!! CAN STAY AS INTS/HEX !!!!

