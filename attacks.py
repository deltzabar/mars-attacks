from OMAC.functions import omacSign, omacKeyGen, omacVerify, u, blockEncrypt

#TODO: generally, check that all attacks discussed exist here.
#TODO: sort out a license


def key_recovery():
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
    print(bytem)
    intm = int.from_bytes(bytem, 'big')
    k0 = blockEncrypt(key[0], b'\0' * 16) #this is using n =128 thus 16 bytes
    L = int.from_bytes(k0, byteorder='big')
    return key, hex(intm ^ L)[2:]


def forgery_one():
    keyString = "1234567890123456"
    k1, k2, k3 = omacKeyGen(str.encode(keyString))
    key = [k1, k2, k3]
    tag1 = KCSign(xi1, key)
    print("tag1 is")
    print(tag1)
    m = "hellohowareyouu"
    m2 = (b'\0' * 16) + str.encode(m)
    print(m2)
    intm2 = int.from_bytes(m2, 'big')
    hexm2 = hex(intm2)
    tag2 = omacSign(k1, k2, k3, hexm2)
    print("tag2 is")
    print(tag2)
    if omacVerify(str.encode(keyString), hexm2, tag1):
        print("Successful forgery")
    print("ended")
    

def forgery_two():
    print("uh huh")


def main():
    key_recovery()
    forgery_one()

main()

