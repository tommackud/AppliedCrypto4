from Crypto.Cipher import AES
import os
import hashlib


def encrypt_AES_GCM(msg):
    kdf_salt = os.urandom(16)
    nonce = os.urandom(16)

    # Encoding of message
    msg = msg.encode()
    secret_key = hashlib.md5(b'8912700384690010128546753346421842971110277912274653120818084388177944029349238676513995291019426567793639980046544018344533404132406609675891391328096219')
    aes_cipher = AES.new(secret_key.digest(), AES.MODE_GCM, nonce=nonce)
    ciphertext, auth_tag = aes_cipher.encrypt_and_digest(msg)

    return kdf_salt, ciphertext, nonce, auth_tag


def decrypt_AES_GCM(encryptedMsg):

    (kdf_salt, ciphertext, nonce, auth_tag) = encryptedMsg

    secret_key = hashlib.md5(b'8912700384690010128546753346421842971110277912274653120818084388177944029349238676513995291019426567793639980046544018344533404132406609675891391328096219')
    aes_cipher = AES.new(secret_key.digest(), AES.MODE_GCM, nonce=nonce)
    plaintext = aes_cipher.decrypt_and_verify(ciphertext, auth_tag)

    # decoding byte data to normal string data
    plaintext = plaintext.decode("utf8")

    return plaintext


print(encrypt_AES_GCM('This is a message from Tom'))
print(decrypt_AES_GCM((b'\xc33\x0eK\x02\xdd\xc5\x08\xf5\xfdU\xbf\x12|\x1c\xaa', b'D\xda\xe3cO`\xa1CY5km\xa0Z\x8e:\xd2\n\xcaC\xda\x88UC\xe1\xe2', b'\xb1\xe8izs\xd8\x8c\xf4C\xb6\xaa\xe5\x14\xc5\xea\xee', b'\xd1\xbd\x930?\xe0(\xb3\xf5"\x00I\xc2f+\xc8')))
