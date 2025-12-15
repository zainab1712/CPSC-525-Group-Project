"""
CPSC 525 F25 Group Project
CWE-215: Insecure Exposure of Sensitive Information to an Unauthorized Actor

Jahnissi Nwakanma - 30174827
Khadeeja Abbas - 30180776
Shanza Raza - 30192765
Zainab Bari - 30154224


entries.py
Manages adding, deleting, listing, and getting vault entries.
"""

from vault import load_vault, save_vault


def create_entry(name: str, username: str, secret: str, notes: str = "") -> dict:
    """Create a new vault entry."""
    return {
        "name": name,
        "username": username,
        "secret": secret,
        "notes": notes or "",  # so notes is always a string
    }


def delete_entry(master_passwd: str, vault_filename: str, name: str) -> bool:
    """Delete an entry by name."""
    vault_data = load_vault(vault_filename, master_passwd)
    if vault_data is None:
        return False

    # Find and separate the entry to delete
    remaining_entries = []
    deleted = False
    for entry in vault_data:
        if entry["name"] == name:
            deleted = True
        else:
            remaining_entries.append(entry)
    if not deleted:
        return False

    # opening the file with w+ mode truncates the file, code for deleting contents from here: https://stackoverflow.com/questions/12277864/python-clear-csv-file
    vault_file_name = vault_filename + ".csv"  # get file name

    try:
        with open(
            vault_file_name, "w", encoding="utf-8"
        ):  
            pass
    except Exception as e:
        print(f"[!] Failed to clear vault file during delete: {e}")
        return False

    # Re-save all the remaining entries
    try:
        for entry in remaining_entries:
            save_vault(entry, vault_filename, master_passwd)
        return True
    except Exception as e:
        print(f"[!] Failed to re-save entries after deletion: {e}")
        return False


def list_entries(master_passwd: str, vault_filename: str) -> list[dict]:
    """List all entries in the vault."""
    vault_data = load_vault(vault_filename, master_passwd)
    if vault_data is None:
        return []
    return vault_data


def get_entry(master_passwd: str, vault_filename: str, name: str) -> dict | None:
    """Get details for a specific entry by name."""
    # --- Decyrpt the data ---
    try:
        vault_data = load_vault(vault_filename, master_passwd)

        if vault_data is None:
            return None

        for e in vault_data:
            if e["name"] == name:
                return e

    except FileNotFoundError:
        print(f"[!] Vault file '{vault_file_name}' not found.")
        return None
    except Exception as e:
        print(f"Failed to get entry: {e}")
        raise

    return None
