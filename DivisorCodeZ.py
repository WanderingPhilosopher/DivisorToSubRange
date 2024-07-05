import random, math, hashlib, base58

def inverse(x, p):
    return pow(x, p - 2, p)

def dblpt(pt, p):
    if pt is None or pt[1] == 0:
        return None
    x, y = pt
    slope = (3 * pow(x, 2, p) * inverse(2 * y, p)) % p
    xsum = (pow(slope, 2, p) - 2 * x) % p
    return (xsum, (slope * (x - xsum) - y) % p)

def addpt(p1, p2, p):
    if p1 is None or p2 is None:
        return None
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        return dblpt(p1, p)
    slope = ((y1 - y2) * inverse(x1 - x2, p)) % p
    xsum = (pow(slope, 2, p) - x1 - x2) % p
    return (xsum, (slope * (x1 - xsum) - y1) % p)

def ptmul(pt, a, p):
    scale = pt
    acc = None
    while a:
        if a & 1:
            acc = addpt(acc, scale, p) if acc else scale
        scale = dblpt(scale, p)
        a >>= 1
    return acc

def ptdiv(pt, a, p, n): 
    return ptmul(pt, inverse(a, n), p)

def getuncompressedpub(compressed_key):
    y_parity = int(compressed_key[:2]) - 2
    x = int(compressed_key[2:], 16)
    a = (pow(x, 3, p) + 7) % p
    y = pow(a, (p + 1) // 4, p)
    if y % 2 != y_parity:
        y = -y % p
    return (x, y)

def compresspub(uncompressed_key):
    x, y = uncompressed_key
    return ('03' if y & 1 else '02') + '{:064x}'.format(x)

def hash160(hex_str):
    sha = hashlib.sha256()
    rip = hashlib.new('ripemd160')
    sha.update(hex_str)
    rip.update(sha.digest())
    return rip.hexdigest()

def getbtcaddr(pubkeyst):
    hex_str = bytearray.fromhex(pubkeyst)
    key_hash = '00' + hash160(hex_str)
    sha = hashlib.sha256()
    sha.update(bytearray.fromhex(key_hash))
    checksum = sha.digest()
    sha = hashlib.sha256()
    sha.update(checksum)
    checksum = sha.hexdigest()[0:8]
    return (base58.b58encode(bytes(bytearray.fromhex(key_hash + checksum)))).decode('utf-8')
   
#secp256k1 constants
Gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
p = 2**256 - 2**32 - 977
g= (Gx,Gy)


compressed_key='023a12bd3caf0b0f77bf4eea8e7a40dbe27932bf80b19ac72f5f5a64925a594196'  #Enter the original public key; the example is a 47 bit key, #52 from the challenge/puzzle
point=getuncompressedpub(compressed_key)
arq1 = open('NewPublicKeyDivisorKeys.txt', 'a')
arq2 = open('NewPublicKeyDivisorKeysLegend.txt', 'a')

divisor = 2**5  #Enter how many public keys you want to shrink the range by; 2^130 - 2^10 = a new range of 2^120
newpub=ptdiv(point,divisor,p,n)

(partGx,partGy)=ptdiv(g,divisor,p,n)

#print ("Compressed NewPUB (",0,")-> ", compresspub(newpub),"addr",getbtcaddr(compresspub(newpub)))

i=0
(pointx,pointy)=(partGx,partGy)
while i<divisor:
    
    (newpubtempx,newpubtempy) = addpt(newpub,(pointx,p-pointy), p)
    (pointx,pointy) = addpt((pointx,pointy),(partGx,partGy), p)
    arq1.write(compresspub((newpubtempx,newpubtempy)) + '\n')
    arq2.write(compresspub((newpubtempx,newpubtempy)) + "      #" + str(i+1) + '\n')
    i=i+1


i = 26 #Enter the public key's number (line position in the file created above)
a = 0x366B085A9E5   #Enter the private key of the public key found
solvedkey = int(a*divisor+i)
print(">%x"%solvedkey)
