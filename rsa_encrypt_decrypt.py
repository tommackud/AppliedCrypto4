import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import ast

random_generator = Random.new().read
key = RSA.generate(1024, random_generator)

public_key = key.publickey()
print('n: ' + str(public_key.n))
print('e: ' + str(public_key.e))
print('Public key: ' + str(public_key.n) + ' ' + str(public_key.e))

ec_pub_key_d_unenc = 4605408159534553736597366043669151574698598193262484584573429284096438228900474579404339194544253862653927555002609
ec_pub_key_Q_unenc = 3808251659837474287418048126952439365969289037053623661965553186849599087224960474693563763065203281900951840590045

ec_encrypted_d = public_key.encrypt(ec_pub_key_d_unenc, 32)
ec_encrypted_Q = public_key.encrypt(ec_pub_key_Q_unenc, 32)

# Ciphertext
print('encrypted d:', ec_encrypted_d)
print('encrypted Q:', ec_encrypted_Q)

ec_decrypted_d = key.decrypt(ast.literal_eval(str(ec_encrypted_d)))
ec_decrypted_Q = key.decrypt(ast.literal_eval(str(ec_encrypted_Q)))

print('decrypted d: ', ec_decrypted_d)
print('decrypted Q: ', ec_decrypted_Q)
