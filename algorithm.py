#The provided code is using pgpy library to perform PGP encryption and decryption on a file.
# import the necessary constants and the pgpy library to use the PGP functions.
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
import pgpy

# PGP key with the RSA encryption algorithm and a key size of 4096 bits. but it could be DSA or ECDSA as well
key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

# # we now have some key material, but our new key doesn't have a user ID yet, and therefore is not yet usable!
uid = pgpy.PGPUID.new('Hemanth Narsingoju', comment='Honest Abe', email='hemanth.narsingoju@gmail.com')

# # now we must add the new user id to the key. We'll need to specify all of our preferences at this point
# # because PGPy doesn't have any built-in key preference defaults at this time
# # this example is similar to GnuPG 2.1.x defaults, with no expiration or preferred keyserver
key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
             hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
             ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
             compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])

# #key.protect("C0rrectPassphr@se", SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
# #with enc_key.unlock("C0rrectPassphr@se")

# # ASCII armored private key
private_key = key

# ASCII armored public key
public_key = key.pubkey

#file_message = pgpy.PGPMessage.new('data.txt',file=True)

#algorithm to perform both enc and dec
# actiontype blog.accenture.com yammer.accenture.com
def pgp_encrypt_decrypt(file_path,encrypt=True):
    if encrypt:
        with open(file_path, 'r+') as f:
            ## PGPMessage will automatically determine if this is a cleartext message or not
            message_from_file = pgpy.PGPMessage.new(f.read())
            #print(message_from_file)
            #enc with public key
            encrypted_message = public_key.encrypt(message_from_file)
            #print(encrypted_message)
            #f.write(str(encrypted_message))
            #dec with private key
    else:
        decrypted_message = private_key.decrypt(encrypted_message).message
        print(decrypted_message)
        with open('enc_'+file_path, "w") as enc:
            enc.write(str(encrypted_message))
        with open('dec_'+file_path, "w") as dec:
            dec.write(str(decrypted_message))



file_path='data.txt'
pgp_encrypt_decrypt(file_path,True)






