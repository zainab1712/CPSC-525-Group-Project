# Person 1: Vault and encryption
# Create and unlock the vault file with the master password.
# Encrypt and decrypt vault contents.
# Read and write the vault file.
# Make sure the vault file always matches what’s in memory. - use hashing: https://medium.com/@info_82002/a-beginners-guide-to-encryption-and-decryption-in-python-12d81f6a9eac

#!/bin/env python3
# ==============================================================================
# Copyright (C) 2025 Pavol Federl pfederl@ucalgary.ca
# do not distribute
# ==============================================================================
#
# You do not need to edit this file. You only need to study it.
# Do not submit this file for grading.
#
# This program reads data from standard input, encrypts it with AES-CTR,
# and writes the encrypted result to standard output. It derives a key for AES
# from a password given to it on the command line, using PBKDF2 algorithm.


import argparse
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def parse_args():
    parser = argparse.ArgumentParser(
        prog="enkrypt",
        description="AES encryptor",
    )
    parser.add_argument("password", help="password used for encryption")
    parser.add_argument("vault", help="valut where the contents are stored")
    parser.add_argument(
        "-d", "--debug", action="store_true", help="""turns on debugging output"""
    )
    parser.add_argument(
        "-nonce",
        type=int,
        default=None,
        help="""if specified, it will be used to create IV and SALT.
        This is a DANGEROUS option, so use at your own risk.""",
    )

    return parser.parse_args()


def key_stretch(password: str, salt: bytes, key_len: int) -> bytes:
    """
    converts a text password to a key (bytes) suitable for AES
    """
    # this makes brute forcing a lot slower if it's hashed repetitively a bunch
    key = PBKDF2HMAC(  # converts a password into a secure key using repetitive hashing
        algorithm=hashes.SHA256(),
        length=key_len,
        salt=salt,
        iterations=10,  # runs iterations 10 times (rlly low amount). Each output (hased once) is fed to the next iteration
    ).derive(password.encode())
    return key


def encrypt(password: str, vault, nonce: int | None = None, debug: bool = False):
    """
    encrypts data from <stdin> and writes encrypted output to <stdout>

    password is any string
    optional iv is a 128-bit integer, or None
    if nonce specified, iv & salt are created using the nonce
    if nonce is None, iv & salt are generated randomly

    iv is used for the CTR block mode
    salt is using to stretch the password to create a key for AES
    """

    if nonce == None:
        iv = os.urandom(16)
        salt = os.urandom(16)
    else:
        print("Warning: non-random nonces are dangerous!", file=sys.stderr)
        iv = nonce.to_bytes(32)[:16]
        salt = nonce.to_bytes(32)[16:]

    # convert password to a key using key stretching
    key = key_stretch(password, salt, 16)

    if debug:
        print(f"#   iv = {iv.hex()}", file=sys.stderr)
        print(f"# salt = {salt.hex()}", file=sys.stderr)
        print(f"#  key = {key.hex()}", file=sys.stderr)

    # write the iv and salt at the beginning of the output
    # these will be needed to decrypt the data
    # sys.stdout.buffer.write(iv + salt)
    iv_and_salt = iv + salt
    

    # make a cipher using the key and iv
    encryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    encrypted_data = b''
    # filename = str(vault) + ".csv"
    # current_directory = os.getcwd()
    # pathname = os.path.join(current_directory,vault)
    # print(filename)
    # with open(filename, "rb") as file:
        # feed stdin to encryptor one block at a time and write out the
        # encrypted date to stdout
    # while True:
    data = vault.encode('utf-8') # this reads a str, we need it in bytes tho
    print(f"{data=}")
    # if len(data) == 0:
    #     break
    cblock = encryptor.update(data)
    print(f"{cblock=}")
    encrypted_data += cblock
        # sys.stdout.buffer.write(cblock)
    # finalize the cipher
    cblock = encryptor.finalize()
    encrypted_data += cblock
    return encrypted_data
    # sys.stdout.buffer.write(cblock)


def main():
    args = parse_args()
    print(f"{args.password=}")
    e_d = encrypt(args.password, args.vault, args.nonce, args.debug)
    print(f"{e_d=}")


if __name__ == "__main__":
    main()
