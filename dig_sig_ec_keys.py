from Crypto.PublicKey import RSA
from hashlib import sha512

keyPair = RSA.generate(bits=1024)
mod = keyPair.n
pub_exp = keyPair.e
pri_exp = keyPair.d
# first_fac = keyPair.p
# second_fac = keyPair.q
# chin_remain = keyPair.u

print('Modulus: ' + str(mod))
print('Modulus len: ' + str(len(str(mod))))

print(f"Public key:  '(n='{hex(keyPair.n)}, e={hex(keyPair.e)})")
# print(f"Private key: (n={hex(keyPair.n)}, d={hex(keyPair.d)})")

# RSA sign the message
ecdh_trip = b'10948989809535500304206060180502130361645633551721297599099675110852037567097436439411425624557398575583760864677561118858742167678564839958609048803329911 2 10170731665243864372056464220616066113470665055148408461844388715921474261990614501358507499242464486624401723699119716132348747891062503333613688486745562'

my_hash = int.from_bytes(sha512(ecdh_trip).digest(), byteorder='big')
signature = pow(my_hash, keyPair.d, keyPair.n)
print("Signature:", signature)

# RSA verify signature
hashFromSignature = pow(signature, keyPair.e, keyPair.n)
print("Signature valid:", my_hash == hashFromSignature)

# Convert message to integer
int_arr = [int(a) for a in ecdh_trip]
int_msg = ''.join([str(elem) for elem in int_arr])
print('Integer message: ' + str(int_msg))
print('Integer message len: ' + str(len(str(int_msg))))
