from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
import pgpy

key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
uid = pgpy.PGPUID.new('Abraham Lincoln', comment='Honest Abe', email='abraham.lincoln@whitehouse.gov')
key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
             hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
             ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
             compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
private_key = key
public_key = key.pubkey

def pgp_encrypt_decrypt(file_path,encrypt=True):
    if encrypt:
        with open(file_path, 'r+') as f:
            message_from_file = pgpy.PGPMessage.new(f.read())
            encrypted_message = public_key.encrypt(message_from_file)
            #print(type(encrypted_message))
            f.seek(0)  # sets  point at the beginning of the file
            f.truncate()  # Clear previous content
            f.write(str(encrypted_message))
        with open('enc'+file_path, "w+") as enc:
            enc.write(str(encrypted_message))
        
    else:
            encrypted_message = pgpy.PGPMessage.from_file("data.txt")
            plaintext = private_key.decrypt(encrypted_message).message
            print(plaintext)
            with open('dec'+file_path, "w+") as dec:
                dec.write(str(plaintext))



file_path='data.txt'
pgp_encrypt_decrypt(file_path,False)






