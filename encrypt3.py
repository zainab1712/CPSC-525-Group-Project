# Source - https://stackoverflow.com/a
# Posted by zwer, modified by community. See post 'Timeline' for change history
# Retrieved 2025-11-26, License - CC BY-SA 3.0

import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

# IV=b"\xa1\\'Y\x1e\x07!K\x04\x11\xc9Q\xd7\xaf\x0e\xf0"
# IV=b'1FG7k32TTYC8JU8a'

def encrypt(key, source, encode=True):
    key = key.encode('utf-8') 
    key = SHA256.new(key).digest()  # IT ONLY HASHES IT ONCE :O # use SHA-256 over our key to get a proper-sized AES key
    # print(f"{key=}")
    IV = Random.new().read(AES.block_size)  # generate IV
    # IV = IV.decode('utf-8')

    # print(f"{IV=}")
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += (bytes([padding]) * padding).decode('utf-8')  # Python 2.x: source += chr(padding) * padding
    # source += (bytes([padding]) * padding) # Python 2.x: source += chr(padding) * padding

    data = IV + encryptor.encrypt(source.encode('utf-8'))  # store the IV at the beginning and encrypt
    # data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt

    return base64.b64encode(data).decode("utf-8") if encode else data

def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode("utf-8"))
    key = key.encode('utf-8') 
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt((source[AES.block_size:]))  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding


def main():    
    password = "everyone"
    cipher_txt = encrypt(password, "ilikecats")
    print(f"{cipher_txt=}")
    # cipher = "4d3lgsqfy+jQnEJbp7pmRKSF1+3SZvIE5uRYqAdj+Su5AqvngfFlNVqg32uyQCPu"
    goal_string = decrypt(password, cipher_txt)
    print(f"{goal_string=}")


if __name__ == "__main__":
    main()