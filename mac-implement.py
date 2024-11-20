import os
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
    
def omacKeyGen(k1: bytes):
    # encrypt n 0s using k1
    k0: bytes = blockEncrypt(k1, b'\0' * 16) #this is using n =128 thus 16 bytes
    intk0: int = int.from_bytes(k0, byteorder='big')
    k2: int = u(intk0)
    k3: int = u(k2) #thus k3 = Lu2
    return k1, k2, k3 

def u(L: int):
    # if most significant b = 0, then simply perform <<1
    C = 0x00000000000000000000000000000087  #this is the constant for n=128
    hexL = hex(L) #converts to hex, for visibility
    #print("hexL: "+hexL)
    binL = bin(L).removeprefix('0b') #converts to binary to allow bitwise comparison
    #print("binL: "+binL)
    if binL[1] == 0:
        #print("starts with 0")
        shiftL: int = L << 1
        return shiftL
     # else, perform <<1
    else:
        #print("starts with 1")
        shiftL: int = (L << 1) ^ C
        #print(hex(shiftL)) 
        return shiftL
   
    # then xor with constant

def OMAC(k1: bytes, k2: int, k3: int, m: str):
    ##TODO: Making assumption here that message is a STRING##
    block, rest = peel(m, 16)
    #check if last block
    if rest != []:
        #create first Enc block
        toEnc: bytes = str.encode(block)
        prevBlock: bytes = blockEncrypt(k1, toEnc)
        intPrevBlock: int = int.from_bytes(prevBlock, byteorder='big')
        while rest != []: #loop while there are still more block to come
            block, rest = peel(rest, 16)
            if rest == []: #if nothing left, do lastblock procedures
                return lastblock(k1, k2, k3, block, prevBlock)
            else:
                intBlock = int.from_bytes(block, byteorder='big')
                xor: int = intPrevBlock ^ intBlock
                prevBlock = blockEncrypt(k1, xor)
                intPrevBlock = int.from_bytes(prevBlock, byteorder='big')
                #perform encryption
    #if yes
    else:
        return lastblock(k1, k2, k3, block, [])


def lastblock(k1: bytes, k2: int, k3: int, m: str, prevBlock: bytes):
    ##TODO:Check types match expected##
    byteM: bytes = str.encode(m)
    intM: int = int.from_bytes(byteM, byteorder='big')
    if prevBlock == []:
        if len(m) == 16:
            last: int = k2 ^ intM
            hexLast: str = hex(last)
            byteLast = bytes.fromhex(hexLast[2:])
            return blockEncrypt(k1, byteLast)
        else:
            ##apply padding
            last: int = k3 ^ intM
            hexLast: str = hex(last)
            byteLast = bytes.fromhex(hexLast[2:])
            return blockEncrypt(k1, last)
    else:
        if len(m) == 16:
            last: int = intM ^ prevBlock ^ k2
            hexLast: str = hex(last)
            byteLast = bytes.fromhex(hexLast[2:])
            return blockEncrypt(k1, last)
        else:
            ##run padding
            last: int = intM ^ prevBlock ^ k3
            hexLast: str = hex(last)
            byteLast = bytes.fromhex(hexLast[2:])
            return blockEncrypt(k2, last)
    
def OMACverif():
    print("placeholder!")

def OMACattack1():
    keyString = "1234567890123456"
    key = str.encode(keyString)
    print("Key is: "+ key.hex())
    k1, k2, k3 = omacKeyGen(key)
    k2String = "CALCULATE THIS" ##TODO: Fix this##
    finalMAC = OMAC(k1, k2, k3, k2String)
    print("Output is: "+ finalMAC.hex())
    calck2 = u(finalMAC)
    ##TODO:Need to convert to BYTE/HEX
    print("Thus, guessed k2 is: "+ calck2.hex())

def test():
    key = "1234567890123456"
    bytesKey = str.encode(key)
    intKey = int.from_bytes(bytesKey, 'big')
    hexfromint = hex(intKey)
    bytefromhex = bytes.fromhex(hexfromint[2:])
    bytefromint = intKey.to_bytes(17, byteorder='big')
    print(key)
    print("converted to bytes is: ")
    print(bytesKey)
    print("from hex that's ")
    print(bytefromhex)
    print("and from int that's ")
    print(bytefromint)
    print("compare hex from int: "+hexfromint)

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
    OMAC(k1, k2, k3, "1234567890123456")
    #test()



main()

##k2 and k3 DONT HAVE TO BE BYTES !!! CAN STAY AS INTS/HEX !!!!

