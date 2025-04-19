from OMAC.functions import omacSign, omacKeyGen, omacVerify, u, blockEncrypt

#TODO: generally, check that all attacks discussed exist here.
#TODO: sort out a license


def key_recovery():
    print("\n[+] Starting key recovery...")
    keyString = "1234567890123456" #a set key string is just used for easy reproducability of results
    key = str.encode(keyString)
    k1, k2, k3 = omacKeyGen(key)
    k2String = (hex(k2))[2:]
    k3String = (hex(k3))[2:]
    finalMAC = omacSign(k1, k2, k3, k2String)
    print("[+] MAC is : "+ finalMAC.hex())
    intMAC = int.from_bytes(finalMAC, 'big')
    calck2 = u(intMAC)
    calck3 = hex(u(calck2))[2:]
    calck2 = (hex(calck2))[2:]
    print("[+] k2 was : "+k2String+" compared to guessed k2 : "+ calck2)
    if (calck2 == k2String):
        print("Successful recovery")
    print("[+] k3 was : "+k3String+" compared to guessed k3 : "+ calck3)
    if (calck3 == k3String):
        print("Successful recovery")

#TODO: move all the stuff across here

#oracle
def KCSign(xi, key: list): #key should be basically an implicit variable to the oracle, but for ease I have done this
    k, m = xi(key)
    tag = omacSign(k[0], k[1], k[2], m)
    return tag


def xi1(key):
    m = "hellohowareyouuu"
    bytem = str.encode(m)
    intm = int.from_bytes(bytem, byteorder='big')
    k0 = blockEncrypt(key[0], b'\0' * 16) #this is using n =128 thus 16 bytes
    L = int.from_bytes(k0, byteorder='big')
    print("m = "+hex(intm ^ L))
    return key, hex(intm ^ L)[2:] #should have xor with L


def forgery_one():
    print("\n[+] Starting forgery 1...")
    keyString = "1234567890123456"
    k1, k2, k3 = omacKeyGen(str.encode(keyString))
    key = [k1, k2, k3]
    print("[+] Submitting xi 1 to oracle")
    tag1 = KCSign(xi1, key)
    print("[+] MAC returned from oracle request is : " + hex(int.from_bytes(tag1, 'big'))[2:])
    m = "hellohowareyouuu"
    m2 = ('0'*32) + hex(int.from_bytes(str.encode(m), 'big'))[2:]
    print("[+] Submitting forgery to be verified")
    if omacVerify(str.encode(keyString), m2, tag1):
        print("Successful forgery")

def xi2(key):
    m = "hellohowareyouuu"
    bytem = str.encode(m)
    intm = int.from_bytes(bytem, 'big')
    delta = 58008
    k2 = key[1] ^ delta
    return [key[0], k2, key[2]], hex(intm)[2:]


def forgery_two():
    print("\n[+] Starting forgery 2...")
    keyString = "1234567890123456"
    k1, k2, k3 = omacKeyGen(str.encode(keyString))
    key = [k1, k2, k3]
    print("[+] Submitting xi 2 to oracle")
    tag1 = KCSign(xi2, key)
    print("[+] MAC returned from oracle request is : " + hex(int.from_bytes(tag1, 'big'))[2:])
    m = "hellohowareyouuu"
    delta = 58008
    bytem = str.encode(m)
    intm = int.from_bytes(bytem, 'big')
    m2 = intm ^ delta
    hexm2 = hex(m2)
    print("[+] Submitting forgery to be verified")
    if omacVerify(str.encode(keyString), hexm2[2:], tag1):
        print("Successful forgery")

def main():
    key_recovery()
    forgery_one()
    forgery_two()

main()

