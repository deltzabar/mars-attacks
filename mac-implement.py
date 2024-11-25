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
    #print("k0 is ")
    #print(k0.hex())
    intk0: int = int.from_bytes(k0, byteorder='big')
    #print("whihc makes intk0: "+hex(intk0))
    k2: int = u(intk0)
    #print("then k2 is: "+hex(k2))
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

def OMAC(k1: bytes, k2: int, k3: int, m: str): #string as hex representation
    ##TODO: Making assumption here that message is a STRING##
    block, rest = peel(m, 32) #32, = 16 bytes
    #check if last block
    if rest != []:
        #create first Enc block
        toEnc: bytes = bytes.fromhex(block)
        prevBlock: bytes = blockEncrypt(k1, toEnc)
        intPrevBlock: int = int.from_bytes(prevBlock, byteorder='big') 
        while rest != []: #loop while there are still more block to come
            block, rest = peel(rest, 32)
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


def lastblock(k1: bytes, k2: int, k3: int, m: str, prevBlock: bytes): #reminder, m = hex
    ##TODO:NEEDS FIXING FOR ONES W PADDING, BUT NOT NEEDED NOW##
    #byteM: bytes = bytes.fromhex(m)
    intM: int = int(m, 16)
    intPrevBlock: int = int.from_bytes(prevBlock, byteorder='big') 
    if prevBlock == []:
        if len(m) == 32:
            last: int = k2 ^ intM
            hexLast: str = hex(last)
            #print("hexLast = "+hexLast)
            byteLast = last.to_bytes(17, byteorder='big')
            #print(byteLast)
            return blockEncrypt(k1, byteLast[1:])
        else:
            ##apply padding
            last: int = k3 ^ intM
            hexLast: str = hex(last)
            #byteLast = bytes.fromhex(hexLast[2:])
            byteLast = last.to_bytes(17, byteorder='big')
            #print(byteLast)
            return blockEncrypt(k1, byteLast[1:])
    else:
        if len(m) == 32:
            last: int = intM ^ intPrevBlock ^ k2 #prevBlock sld be int
            hexLast: str = hex(last)
            byteLast = bytes.fromhex(hexLast[2:])
            return blockEncrypt(k1, last)
        else:
            ##run padding
            last: int = intM ^ intPrevBlock ^ k3
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
    k2String = (hex(k2))[2:]
    finalMAC = OMAC(k1, k2, k3, k2String)
    print("Output is: "+ finalMAC.hex())
    hexMAC = finalMAC.hex()
    intMAC = int.from_bytes(finalMAC, 'big')
    calck2 = u(intMAC)
    ##TODO:Need to convert to BYTE/HEX
    print("Key string is: "+k2String+" compared to guessed k2: "+ hex(calck2))

def reverseKey(k2: str):
    C = 0x00000000000000000000000000000087
    bytesKey = str.encode(k2)
    intKey = int.from_bytes(bytesKey, 'big')
    intKey = (intKey ^ C) >> 1
    return intKey

def test():
    key = "1234567890123456"
    bytesKey = str.encode(key)
    intKey = int.from_bytes(bytesKey, 'big')
    hexfromint = hex(intKey)
    intfromhex = int(hexfromint, 16)
    bytefromhex = bytes.fromhex(hexfromint[2:])
    bytefromint = intKey.to_bytes(17, byteorder='big')
    print(key)
    print("converted to bytes is: ")
    print(bytesKey)
    print("from hex that's ")
    print(bytefromhex)
    print("and from int that's ") ##this is the one that doesn't match
    print(bytefromint)
    print("compare hex from int: "+hexfromint+" and from bytes: "+bytesKey.hex())
    print("compare int from string: "+str(intKey)+" and int from hex: "+str(intfromhex))

def main():
    setup()
    key = os.urandom(32)
    #print("key: "+key.hex())
    #ctxt = blockEncrypt(key, b"1111111111111111")
    #print(ctxt)
    #output = blockDecrypt(key, ctxt)
    #print(output)
    #message = "12345678901234567890"
    #first, second = peel(message, 16)
    #toEnc = str.encode(first)
    #print(blockDecrypt(key, blockEncrypt(key, toEnc)))
    k1, k2, k3 = omacKeyGen(key)
    #OMAC(k1, k2, k3, "1234567890123456")
    #test()
    OMACattack1()



main()

##TODO: Causing issues bc if you get no. too small as int, won't convert to full-size hex##
##switch to using bytes, work out how to cut off first/last byte##

