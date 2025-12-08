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

def list_entries(vault_data):
    """List all entries in the vault."""
    entries = vault_data.get("entries", [])
    return entries

def get_entry(vault_name, name):
    """Get details for a specific entry by name."""
    vault_file_name = str(vault_name) + ".csv"
    all_entries_names = []
    with open(vault_file_name) as f:
        line_of_vault_data = f.readline()
        print(line_of_vault_data)
        line_of_vault_data = ast.literal_eval(line_of_vault_data)
        entries = line_of_vault_data.get("name", [])
        all_entries_names.append(entries)
        
        
    for e in all_entries_names:
        # decrypt the name
        #----------> here
        if e == name:
            return e
    return None
