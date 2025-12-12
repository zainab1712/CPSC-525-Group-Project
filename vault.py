"""
CPSC 525 F25 Group Project
CWE-215: Insecure Exposure of Sensitive Information to an Unauthorized Actor

Jahnissi Nwakanma - 
Khadeeja Abbas - 30180776
Shanza Raza - 30192765
Zainab Bari - 30154224


vault.py
Handles creating, unlocking, reading, and writing the encrypted vault file.
"""
import pandas as pd
import csv
from encrypt3 import encrypt, decrypt
import pickle
import ast


def init_vault(vault, master_password: str):
    """Create a new encrypted vault file using the master password."""
    vault_file_name = str(vault) + ".csv"  # create csv file name
    f = open(vault_file_name, "w", newline="")  # create file
    vault_dictionary = {}  # redundant
    return vault_dictionary


def load_vault(vault, master_password: str):
    """Unlock and decrypt the existing vault file."""
    try:
        vault_file_name = str(vault) + ".csv"  # get file name
        vault_data = []
        with open(vault_file_name, "r") as file:
            while (
                line := file.readline()
            ):  # safer to go line by line than just doing read()
                encrypted_data = line
                encrypted_data = ast.literal_eval(
                    encrypted_data
                )  # make the 'str' be read as a dict
                try:
                    # decrypt all the encrypted values
                    decrypted_name = decrypt(master_password, encrypted_data["name"])
                    decrypted_username = decrypt(
                        master_password, encrypted_data["username"]
                    )
                    decrypted_secret = decrypt(
                        master_password, encrypted_data["secret"]
                    )
                    decrypted_notes = decrypt(master_password, encrypted_data["notes"])
                    decrypted_dict = {
                        "name": decrypted_name,
                        "username": decrypted_username,
                        "secret": decrypted_secret,
                        "notes": decrypted_notes,
                    }
                except ValueError as e:
                    print("Wrong password")
                    return None
                vault_data.append((decrypted_dict))
        return vault_data
    except Exception as e:
        print(f"Failed to load vault: {e}")
        raise

def save_vault(vault_data, vault_name, master_password: str):
    """Encrypt and save the vault data to the file."""
    # the given vault data is a dictionary, this takes the values of the dict and encrypts them
    encrypted_name = encrypt(master_password, vault_data["name"])
    encrypted_username = encrypt(master_password, vault_data["username"])
    encrypted_secret = encrypt(master_password, vault_data["secret"])
    encrypted_notes = encrypt(master_password, vault_data["notes"])

    # creating a new dictionary to add to the csv file
    adding_dict = {
        "name": encrypted_name,
        "username": encrypted_username,
        "secret": encrypted_secret,
        "notes": encrypted_notes,
    }

    vault_file_name = str(vault_name) + ".csv"  # get file name
    with open(vault_file_name, "a") as f:
        f.write(str(adding_dict) + "\n")  # write our new dictionary to the file
    return


# the below functions aren't separetly used
def encrypt_data(data, key):
    """Encrypt data using the provided key."""
    encrypted_data = encrypt(key, data)
    return encrypted_data


def decrypt_data(data, key):
    """Decrypt data using the provided key."""
    pass
