from Crypto.PublicKey import RSA
from hashlib import sha512

msg_dQ = b'4605408159534553736597366043669151574698598193262484584573429284096438228900474579404339194544253862653927555002609 3808251659837474287418048126952439365969289037053623661965553186849599087224960474693563763065203281900951840590045 '

keyPair = RSA.generate(bits=1024)
print(f"Public key:  (n={hex(keyPair.n)}, e={hex(keyPair.e)})")
print(f"Private key: (n={hex(keyPair.n)}, d={hex(keyPair.d)})")

# RSA sign the message
hash_dQ = int.from_bytes(sha512(msg_dQ).digest(), byteorder='big')
signature_dQ = pow(hash_dQ, keyPair.d, keyPair.n)
print("Signature dQ:", hex(signature_dQ))

# RSA verify signature
hash_dQ = int.from_bytes(sha512(msg_dQ).digest(), byteorder='big')
hashFromSignature_dQ = pow(signature_dQ, keyPair.e, keyPair.n)
print("Signature valid (dQ):", hash_dQ == hashFromSignature_dQ)

