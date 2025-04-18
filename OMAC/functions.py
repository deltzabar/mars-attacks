import os
#import block cipher primitives to use in OMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def setup():
    global iv
    iv = os.urandom(16)

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
    
def u(L: int):
    C = 0x00000000000000000000000000000087  #this is the constant for n=128
    #hexL = hex(L) #converts to hex, for visibility
    binL = bin(L).removeprefix('0b') #converts to binary to allow bitwise comparison
    # if most significant b = 0, then simply perform <<1
    if binL[1] == 0:
        shiftL: int = L << 1
        binShift = bin(shiftL)
        if (len(binShift) > 130):
            final = int(binShift[3:], 2)
        else: 
            final = shiftL
        return final
    #else, also xor in the constant
    else:
        shiftL: int = (L << 1) ^ C
        binShift = bin(shiftL)
        if (len(binShift) > 130):
            final = int(binShift[3:], 2)
        else: 
            final = shiftL
        return final

#using definition of padding where we do '1' plus the number of 0s needed to fill up the block  
#please make sure i'm stripped first :)
def padder(block: str): #block is in hex
    binB = bin(int(block, 16))
    binB = binB + '1' + ('0' * (127 - len(binB)))
    return hex(int(binB[2:], 2))[2:]


def lastblock(k1: bytes, k2: int, k3: int, m: str, prevBlock: bytes): #reminder, m = hex
    if prevBlock == []:
        prevBlock = b'\0' * 16
    intPrevBlock: int = int.from_bytes(prevBlock, byteorder='big')
    #if a full block, we xor with K2
    if len(m) == 32:
        intM: int = int(m, 16)
        last: int = intM ^ intPrevBlock ^ k2 
        hexLast: str = hex(last)
        newHex = ('0' * (32 - len(hexLast.removeprefix('0x')))) + hexLast.removeprefix('0x') 
        byteLast = bytes.fromhex(newHex)
        return blockEncrypt(k1, byteLast)
    else:
    #if not a full block, we need to pad first, then xor with K3
        padded = padder(m)
        intM = int(padded, 16)
        last: int = intM ^ intPrevBlock ^ k3
        hexLast: str = hex(last)
        newHex = ('0' * (32 - len(hexLast.removeprefix('0x')))) + hexLast.removeprefix('0x')
        byteLast = bytes.fromhex(newHex)
        return blockEncrypt(k1, byteLast)
        
def omacKeyGen(k1: bytes):
    # encrypt n 0s using k1
    k0: bytes = blockEncrypt(k1, b'\0' * 16) #this is using n =128 thus 16 bytes
    intk0: int = int.from_bytes(k0, byteorder='big')
    k2: int = u(intk0)
    k3: int = u(k2) #thus k3 = Lu2
    return k1, k2, k3 
   
def omacSign(k1: bytes, k2: int, k3: int, m: str): #string as hex representation
    block, rest = peel(m, 32) #32, = 16 bytes
    #check if last block
    if rest != []:
        toEnc: bytes = bytes.fromhex(block)
        H: bytes = blockEncrypt(k1, toEnc) 
        intH: int = int.from_bytes(H, byteorder='big') 
        while rest != []: #loop while there are still more blocks to come
            block, rest = peel(rest, 32)
            if rest == []: #if nothing left, do lastblock procedures
                return lastblock(k1, k2, k3, block, H)
            else:
                intBlock = int.from_bytes(block, byteorder='big')
                xor: int = intH ^ intBlock
                H = blockEncrypt(k1, xor)
                intH = int.from_bytes(H, byteorder='big')
    #if yes
    else:
        return lastblock(k1, k2, k3, block, [])

    
def omacVerify(k1, m, tag):
    #very simply, generate expected tag and check it matches
    k1, k2, k3 = omacKeyGen(k1)
    tagPrime = omacSign(k1, k2, k3, m) 
    if tagPrime == tag:
        return True
    else:
        return False

#TODO: make sure this works
def reverseKey(k2: str):
    C = 0x00000000000000000000000000000087
    bytesKey = str.encode(k2)
    intKey = int.from_bytes(bytesKey, 'big')
    intKey = (intKey ^ C) >> 1
    return intKey

def main():
    setup()

main()