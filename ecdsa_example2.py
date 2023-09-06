import hashlib
from ecdsa import SigningKey, NIST256p , numbertheory
from ecdsa.ellipticcurve import Point
import ecdsa

import random
import os

def extended_gcd(a, b):
    if b == 0:
        return (a, 1, 0)
    else:
        d, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return (d, x, y)

def multiplicative_inverse(a, n):
    d, x, y = extended_gcd(a, n)
    if d != 1:
        raise ValueError("The multiplicative inverse does not exist")
    else:
        return x % n


file_name = "output"

idx = 0
#=====rand=====
# while (idx < 100):
    #dbg===
while (idx < 1):
    idx+=1
    #dbg===
    # private_key = SigningKey.generate(curve=NIST256p)
    

    # k_int = random.randint(order-32, order-1)

    #  ====KAT======
    private_key_hex = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
    private_key_bytes = bytes.fromhex(private_key_hex)
    private_key = SigningKey.from_string(private_key_bytes, curve=NIST256p)
    k_hex = "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60"
    k_int = int(k_hex,16)


    curve_name = private_key.curve.name
    G = private_key.curve.generator
    print(f"G = {G.x()} , {G.y()}")
    print(f"curve_name = {curve_name}")   
    order = private_key.curve.generator.order()
    print(f"order_hex = {hex(order)}")
    print(f"order_int = {int(order)}")
    public_key = private_key.verifying_key

    private_key_hex = private_key.to_string().hex()
    public_key_hex = public_key.to_string().hex()

    public_key_bytes = public_key.to_string()

    ux = int.from_bytes(public_key_bytes[:32], byteorder='big')
    uy = int.from_bytes(public_key_bytes[32:], byteorder='big')
    ux_hex = hex(ux)
    uy_hex = hex(uy)
    Q = public_key.pubkey.point

    print(f"Private Key: {private_key_hex}")
    print(f"Public Key: {public_key_hex}")
    print(f"Public Key (ux): {ux_hex}")
    print(f"Public Key (uy): {uy_hex}")

    # message_length = random.randint(0,1024)
    # message = os.urandom(message_length)
    message = b"sample"
    message_length =len(message)
    print(f"msg_len = {message_length}")
    print(f"msg = {(message.hex())}")
    e_byte = hashlib.sha256(message).digest()
    e_hex = e_byte.hex()
    print(f"e_hex = {(e_hex)}")
    print(f"e_int = {(int(e_hex,16))}")

    signature = private_key.sign(message,hashfunc=hashlib.sha256,k=k_int)
    # r = signature.r
    # s = signature.s
    r, s = signature[:32], signature[32:]
    print(f"signature = {signature}")
    # r_hex = "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
    # s_hex = "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"
    # r = int(r_hex,16)

    print(f"r = {r.hex()}")
    print(f"s = {s.hex()}")
    print(f"r_int = {int(r.hex(),16)}")
    print(f"s_int = {int(s.hex(),16)}")
    print("signature:")
    print(signature.hex())


    s_int = int.from_bytes(s, byteorder='big')
    print(f"s_int = {s_int}")
    print(f"order = {order}")
    c_sinv = multiplicative_inverse(s_int, order) #correct
    print(f"c = s^-1 mod n = {c_sinv}")
    cal_u1 = ((int(e_hex,16) * c_sinv) % order)  
    # e*c = 5536788856131197834474991438633800834774713107866660568132691507817751225680111716911624993594860029947175619565670227373506734536293453280022460487482453
    # mod order : 76802929953564841014745990121047686326403956053371139132425205714078128822337
    print(f"u1 = e*c mod n = {cal_u1}")
    r_int = int.from_bytes(r, byteorder='big')
    cal_u2 = ((r_int * c_sinv) % order)
    # r*c = 7580518420274355287472345797030454017337070184722691795483088616946757365108053876377051026766960438892936939099563588761110220825869819761502817137345842
    # mod order = 32955858153445698164125015627026694558773479180781844519416553310382593614109
    # cal_u2 = ((int(r) * int(c_sinv)) % order)
    print(f"u2 = r*c mod n = {cal_u2}")
    gx = 48439561293906451759052585252797914202762949526041747995844080717082404635286
    R = (cal_u1*G+cal_u2*Q) 
    v = R.x() % order
    print(f"cal_u1*gx = {cal_u1*G}")
    print(f"cal_u2*ux = {cal_u2*Q}")
    print(f"R = {R}")
    print(f"v = {v}")
    print(f"r = {int(r.hex(),16)}")
    if(v != int(r.hex(),16)):
        raise ValueError("R != r")
    if( (order - cal_u1 <=32) and (order - cal_u1 >0) ):
    # if( cal_u1 >= 0 ):
        print("get the case!")
        idx +=1
        print(f"n - u1 = {order-cal_u1}")
        with open(file_name+f"_{idx}"+".txt", "w") as file:
            file.write(f"curve_name = {curve_name}\n")
            file.write(f"order_hex = {hex(order)}\n")
            file.write(f"Private Key: {private_key_hex}\n")
            file.write(f"Public Key: {public_key_hex}\n")
            file.write(f"Public Key (ux): {ux_hex}\n")
            file.write(f"Public Key (uy): {uy_hex}\n")
            file.write(f"msg_len = {message_length}\n")
            file.write(f"msg = {(message.hex())}\n")
            file.write(f"r = {r.hex()}\n")
            file.write(f"s = {s.hex()}\n")
            file.write(f"s_int = {s_int}\n")
            file.write(f"order = {order}\n")
            file.write(f"c = s^-1 mod n = {c_sinv}\n")
            file.write(f"u1 = e*c mod n = {cal_u1}\n")
            file.write(f"n - u1 = {order-cal_u1}\n")
    else :
        print("get value fail...")
    try:
        public_key.verify(signature, message,hashfunc=hashlib.sha256)
        print("signature valid")
        print(f"R = {r.hex()}")
        print(f"S = {s.hex()}")
        print(f"Qx = {ux_hex}")
        print(f"Qy = {uy_hex}")
        print(f"e = {e_hex}")
        print(f"n = {hex(order)}")
        print(f"k = {hex(k_int)}" + f" = n - {order - k_int}")

    except :
        print("signature invalid , ERROR!!!")
        print(ValueError)




# curve: NIST P-256

#    q = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
#    (qlen = 256 bits)

#    private key:

#    x = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721

#    public key: U = xG

#    Ux = 60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6

#    Uy = 7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299

#    Signatures:

#    With SHA-1, message = "sample":
#    k = 882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4
#    r = 61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32
#    s = 6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB

#    With SHA-224, message = "sample":
#    k = 103F90EE9DC52E5E7FB5132B7033C63066D194321491862059967C715985D473
#    r = 53B2FFF5D1752B2C689DF257C04C40A587FABABB3F6FC2702F1343AF7CA9AA3F
#    s = B9AFB64FDC03DC1A131C7D2386D11E349F070AA432A4ACC918BEA988BF75C74C

#    With SHA-256, message = "sample":
#    k = A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
#    r = EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
#    s = F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8

#    With SHA-384, message = "sample":
#    k = 09F634B188CEFD98E7EC88B1AA9852D734D0BC272F7D2A47DECC6EBEB375AAD4
#    r = 0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719
#    s = 4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954

#    With SHA-512, message = "sample":
#    k = 5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5
#    r = 8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00
#    s = 2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE