# Person 1: Vault and encryption
# Create and unlock the vault file with the master password.
# Encrypt and decrypt vault contents.
# Read and write the vault file.
# Make sure the vault file always matches what’s in memory. - use hashing: https://medium.com/@info_82002/a-beginners-guide-to-encryption-and-decryption-in-python-12d81f6a9eac


# code based off of: https://medium.com/@info_82002/a-beginners-guide-to-encryption-and-decryption-in-python-12d81f6a9eac

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt(msg, public_key):
    msg_in_bytes = msg.encode('utf-8')
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key)) # creates a new object of type PKCS1... and that is specific type of encryption that also uses the public key. it also adds padding
    cipher_text = cipher_rsa.encrypt(msg_in_bytes) # encrypts the message but also adds padding from PKCS1...
    return cipher_text

def decrypt(encrypted_msg, private_key):
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
    plain_text = cipher_rsa.decrypt(encrypted_msg)
    return plain_text.decode() # makes the byte string into a string


def main():
    private_key, public_key = generate_rsa_keys()
    print(f"private key: {private_key},\n public key: {public_key}\n")
    
    cipher_txt = encrypt("I like dogs", public_key)
    print(f"{cipher_txt=}")
    
    goal_string = decrypt(cipher_txt, private_key)
    print(f"{goal_string=}")


if __name__ == "__main__":
    main()
