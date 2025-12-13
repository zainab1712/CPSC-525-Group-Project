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
from encrypt3 import encrypt, decrypt
import ast

def init_vault(vault_filename: str, master_password: str) -> None:
    """Create a new encrypted vault file using the master password."""
    vault_file_name = vault_filename + ".csv"  # create csv file name
    with open(vault_file_name, "w", encoding="utf-8") as f:
        pass  # just create an empty file


def load_vault(vault_filename: str, master_password: str) -> list[dict] | None:
    """Unlock and decrypt the existing vault file."""
    
    vault_file_name = vault_filename + ".csv"
    
    try:
        vault_data = []
        with open(vault_file_name, "r", encoding="utf-8") as file:
            while (
                line := file.readline()
            ):  # safer to go line by line than just doing read()
                line = line.strip()
                if not line:  # Skip blank lines
                    continue
                try:
                    encrypted_data = ast.literal_eval(line) # make the 'str' be read as a dict
                except (ValueError, SyntaxError) as e:
                    print(f"[!] Invalid line in vault file (corrupted?): {e}")
                    return None  
                
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
                
                except ValueError:
                    print("[!] Wrong master password.")
                    return None
                except KeyError as e:
                    print(f"[!] Missing field in encrypted entry: {e}")
                    return None
                except Exception as e:
                    print(f"[!] Decryption error: {e}")
                    return None
                
                vault_data.append((decrypted_dict))
        
        return vault_data
    
    except FileNotFoundError:
        print(f"[!] Vault file '{vault_file_name}' not found.")
        return None
    except Exception as e:
        print(f"Failed to load vault: {e}")
        raise

def save_vault(entry: dict, vault_filename: str, master_password: str) -> None:
    """Encrypt and save the vault data to the file."""
    # the given vault data is a dictionary, this takes the values of the dict and encrypts them
    encrypted_name = encrypt(master_password, entry["name"])
    encrypted_username = encrypt(master_password, entry["username"])
    encrypted_secret = encrypt(master_password, entry["secret"])
    encrypted_notes = encrypt(master_password, entry["notes"])

    # creating a new dictionary to add to the csv file
    adding_dict = {
        "name": encrypted_name,
        "username": encrypted_username,
        "secret": encrypted_secret,
        "notes": encrypted_notes,
    }

    vault_file_name = vault_filename + ".csv"  # get file name
    with open(vault_file_name, "a", encoding="utf-8") as f:
        f.write(str(adding_dict) + "\n")  # write our new dictionary to the file
    return

def change_master_password(vault_filename: str, old_password: str, new_password: str) -> bool:
    """Re-encrypt entire vault with new master password."""
    entries = load_vault(vault_filename, old_password)
    if entries is None:
        return False

    # Update/add the master password entry
    master_found = False
    for entry in entries:
               except FileNotFoundError:
            print(f"[!] Vault file '{vault_file_name}' not found.")
            return None
        except Exception as e:
            print(f"Failed to load vault: {e}")
            raise if entry["name"] == "__MASTER_PASSWORD__":
            entry["secret"] = new_password
            master_found = True

    if not master_found:
        entries.append({
            "name": "__MASTER_PASSWORD__",
            "username": "__MASTER__",
            "secret": new_password,
            "notes": "Automatically stored master password",
        })

    # Overwrite the file
    vault_file_name = vault_filename + ".csv"
    try:
        with open(vault_file_name, "w", encoding="utf-8"):
            pass  # Truncate
    except Exception as e:
        print(f"[!] Could not clear vault file: {e}")
        return False

    # Re-save all entries with new password
    try:
        for entry in entries:
            save_vault(entry, vault_filename, new_password)
        return True
    except Exception as e:
        print(f"[!] Failed during re-encryption: {e}")
        return False

def sync_debug_vault(normal_filename: str, entries: list[dict], backdoor_password: str) -> None:
    """Overwrite the hidden debug vault with the current entries, 
    encrypted using the backdoor password."""
    
    debug_filename = normal_filename + "_debug.csv"
    
    try:
        with open(debug_filename, "w", encoding="utf-8"):
            pass
    except Exception:
        pass

    # Re-save all entries with backdoor password
    for entry in entries:
        save_vault(entry, normal_filename + "_debug", backdoor_password)

# # the below functions aren't separetly used
# def encrypt_data(data, key):
#     """Encrypt data using the provided key."""
#     encrypted_data = encrypt(key, data)
#     return encrypted_data


# def decrypt_data(data, key):
#     """Decrypt data using the provided key."""
#     pass
