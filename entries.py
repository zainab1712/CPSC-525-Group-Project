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
from vault import load_vault


def create_entry(name, username, secret, notes):
    """Create a new vault entry."""
    return {
        "name": name,
        "username": username,
        "secret": secret,
        "notes": notes,
    }


def delete_entry(vault_data, name):
    """Delete an entry by name."""
    entries = vault_data.get("entries", [])
    count = 0
    for e in entries:
        if e.get("name") == name:
            del entries[count]
            return True
        count = count + 1
    return False


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
