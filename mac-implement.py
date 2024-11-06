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
    k0 = blockEncrypt(k1, b'\0' * 16) #this is using n =128 thus 16 bytes
    k2 = u(k0)
    k3 = u(k2) #thus k3 = Lu2
    return k1, k2, k3 

def u(L):
    # if most significant b = 0, then simply perform <<1
    C = 0x00000000000000000000000000000087  #this is the constant for n=128
    hexL = L.hex() #converts to hex, for visibility & to then move to binary
    print("hexL: "+hexL)
    binL = bin(int(hexL, base=16)).removeprefix('0b') #converts to binary to allow bitwise comparison
    intL = int.from_bytes(L, byteorder='big') #convert to int for bitwise operations
    print("binL: "+binL)
    if binL[1] == 0:
        print("starts with 0")
        shiftL = intL << 1
        byteL = shiftL.to_bytes(17, byteorder='big')
        print("post shift: "+str(shiftL)+" and as hex: " + byteL.hex())
        return byteL #WHY won't it accept 16??? i don't understand
     # else, perform <<1
    else:
        print("starts with 1")
        shiftL = (intL << 1) ^ C
        byteL = shiftL.to_bytes(17, byteorder='big')
        print("post shift: "+str(shiftL)+" and as hex: " + byteL.hex())
        return byteL 
   
    # then xor with constant
    



def main():
    setup()
    key = os.urandom(32)
    print("key: "+key.hex())
    #ctxt = blockEncrypt(key, b"1111111111111111")
    #print(ctxt)
    #output = blockDecrypt(key, ctxt)
    #print(output)
    message = "12345678901234567890"
    first, second = peel(message, 16)
    toEnc = str.encode(first)
    #print(blockDecrypt(key, blockEncrypt(key, toEnc)))
    omacKeyGen(key)



main()


