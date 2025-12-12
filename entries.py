"""
CPSC 525 F25 Group Project
CWE-215: Insecure Exposure of Sensitive Information to an Unauthorized Actor

Jahnissi Nwakanma - 
Khadeeja Abbas - 30180776
Shanza Raza - 30192765
Zainab Bari - 30154224


entries.py
Manages adding, deleting, listing, and getting vault entries.
"""
import ast
from vault import load_vault, save_vault


def create_entry(name, username, secret, notes):
    """Create a new vault entry."""
    return {
        "name": name,
        "username": username,
        "secret": secret,
        "notes": notes,
    }


def delete_entry(master_passwd, vault_name, name):
    """Delete an entry by name."""
    vault_data = load_vault(vault_name, master_passwd)
    print("VAULT DATA!!!! ",vault_data , "\n\n\n")

    # opening the file with w+ mode truncates the file
    vault_file_name = str(vault_name) + ".csv"  # get file name

    f = open(vault_file_name, "w+") # THIS SHOULD DELETE THE FILE CONTENTS NOT SURE
    f.close()
    
    flag = False
    for idx, e in enumerate(vault_data):
        if (e.get("name", [])).decode("utf-8") == name:
            flag = True
        else:
            print("this is e: ",e)
            for key, value in e.items():
                e[key] = value.decode("utf-8")
            save_vault(e, vault_name, master_passwd)
    return flag

def list_entries(master_passwd, vault_name):
    """List all entries in the vault."""
    vault_data = load_vault(vault_name, master_passwd)
    print(f"{vault_data=}")
    return vault_data


def get_entry(master_passwd, vault_name, name):
    """Get details for a specific entry by name."""
    # --- Decyrpt the data ---
    vault_data = load_vault(vault_name, master_passwd)

    for e in vault_data:
        if (e.get("name", [])).decode("utf-8") == name:
            return e
    return None
