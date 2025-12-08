"""
CPSC 525 F25 Group Project
CWE-215: Insecure Exposure of Sensitive Information to an Unauthorized Actor

Jahnissi Nwakanma - 
Khadeeja Abbas - 30180776
Shanza Raza - 
Zainab Bari - 30154224


vault.py
Handles creating, unlocking, reading, and writing the encrypted vault file.
"""
import pandas as pd
import csv
# from encrypt4 import encrypt
from encrypt3 import encrypt, decrypt
import pickle
import ast

def init_vault(vault, master_password: str):
    """Create a new encrypted vault file using the master password."""
    vault_file_name = str(vault) + ".csv"
    f = open(vault_file_name, 'w', newline='')
    # with open(vault_file_name, 'w', newline='') as f:
    #     headers = ['entries', 'name', 'username', 'secret', 'notes']
    #     writer = csv.DictWriter(f, fieldnames=headers)
    #     writer.writeheader()
        # Now write a sample row:
        # row = {'Song_Name': 'Dumb', 'Artist_Name': 'Nirvana'}
        # writer.writerow(row)  # Automatically skips missing keys
    # df = pd.read_csv(vault_file_name, header=None)
    # print(df)
    # headers = ['entries', 'name', 'username', 'secret', 'notes']
    vault_dictionary = {}

    # for header in headers:
        # vault_dictionary[header] = None  # Or "" for empty string values

    return vault_dictionary

def load_vault(vault, master_password: str):
    """Unlock and decrypt the existing vault file."""
    try:
        vault_file_name = str(vault) + ".csv"
        vault_data = []
        with open(vault_file_name, "r") as file:
            # for line in file:
            while line := file.readline():
                encrypted_data = line
                encrypted_data = ast.literal_eval(encrypted_data)

                # encrytped_data = encrypted_data.decode('utf-8') 
                print(encrypted_data)
                try:
                    # decrypted_data = decrypt(master_password.encode("utf-8"), encrypted_data, decode = False)
                    decrypted_name = decrypt(master_password, encrypted_data['name'])
                    decrypted_username = decrypt(master_password, encrypted_data['username'])
                    decrypted_secret = decrypt(master_password, encrypted_data['secret']) 
                    decrypted_notes = decrypt(master_password, encrypted_data['notes'])
                    decrypted_dict = {'name':decrypted_name, 'username':decrypted_username, 'secret':decrypted_secret, 'notes':decrypted_notes}
                    print(f"{decrypted_dict=}")
                #decrypted_data = decrypt_data(encrypt_data,master_password)
                except ValueError as e:
                    print("Wrong password")
                    return None
                vault_data.append((decrypted_dict))
        return vault_data    
    except Exception as e:
        print(f"Failed to load vault: {e}")
        raise
    pass

def save_vault(vault_data, vault_name, master_password: str):
    """Encrypt and save the vault data to the file."""
    print(vault_data)
    # the given vault data is a dictionary, this converts encrypts it and then converts it into the csv file
    encrypted_name = encrypt(master_password, vault_data['name'])
    encrypted_username = encrypt(master_password, vault_data['username'])
    encrypted_secret = encrypt(master_password, vault_data['secret'])
    encrypted_notes = encrypt(master_password, vault_data['notes'])
    adding_dict = {'name':encrypted_name, 'username':encrypted_username, 'secret':encrypted_secret, 'notes':encrypted_notes}
    # vault_data = encrypted_data
    print(adding_dict)
    vault_file_name = str(vault_name) + ".csv"
    with open(vault_file_name, 'a') as f:
        # headers = ['name', 'username', 'secret', 'notes']
        f.write(str(adding_dict) + "\n")
        # data_dic = dict(zip(headers, vault_data))
        # print(data_dic)
        # writer = csv.DictWriter(f, fieldnames=headers)
        # writer = csv.writer(f)
        # writer = csv.DictWriter(f, fieldnames=headers)
        # writer.writeheader()
        # Now write a sample row:
        # print(vault_data.keys()) # Output: dict_keys(['name', 'age'])

        # row = adding_dict
        # for val in adding_dict:
            # byval = val.encode('utf-8')
        # writer.writerow(str(adding_dict))  # Automatically skips missing keys
        # writer.writerow("\n")
        # writer.writerows(adding_dict)
    return

def encrypt_data(data, key):
    """Encrypt data using the provided key."""
    encrypted_data = encrypt(key, data)
    return encrypted_data

def decrypt_data(data, key):
    """Decrypt data using the provided key."""
    
    
    pass
