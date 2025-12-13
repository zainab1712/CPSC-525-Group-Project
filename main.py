"""
CPSC 525 F25 Group Project
CWE-215: Insecure Exposure of Sensitive Information to an Unauthorized Actor

Jahnissi Nwakanma - 
Khadeeja Abbas - 30180776
Shanza Raza - 30192765
Zainab Bari - 30154224


main.py
Handles the different commands and their functionalities.
"""

import datetime
from vault import init_vault, load_vault, save_vault, change_master_password, sync_debug_vault
from entries import create_entry, delete_entry, get_entry, list_entries
import os
# https://docs.python.org/3/library/pickle.html
import pickle

DEBUG_DUMP_PASSWORD = "debugdump123"

"""Append a timestamped message to logfile.
Returns the full path to the logfile."""


def log_action(message: str, logfile: str = "vault.log"):
    now = datetime.datetime.now()

    ts = now.isoformat(sep="T", timespec="auto") + "Z"
    entry = f"{ts} - {message}\n"
    with open(logfile, "a", encoding="utf-8") as f:
        f.write(entry)
    return os.path.abspath(logfile)


"""Handle the 'init' command."""


def handle_init(vault_filename: str, master_passwd: str) -> str:
    # Initialize a new vault with the given master password
    init_vault(vault_filename, master_passwd)

    # Store the master password as a vault entry
    master_entry = create_entry(
        name="__MASTER_PASSWORD__",
        username="__MASTER__",
        secret=master_passwd,
        notes=f"Automatically stored master password for '{vault_filename}'.csv",
    )

    # Save the vault
    # print("master entry: ", master_entry)
    save_vault(master_entry, vault_filename, master_passwd)
    sync_debug_vault(vault_filename, [master_entry], DEBUG_DUMP_PASSWORD)
    print("[OK] Vault initialized.")
    log_action("Vault initialized successfully and master password stored as entry.")
    return vault_filename


"""Handle the 'add' command."""


def handle_add(vault_data: list, master_passwd: str, vault_filename: str) -> list:    # Check that the vault is loaded
    if vault_data is None or vault_filename is None:
        print("[!] No vault loaded.")
        return vault_data

    # print(vault)
    # Prompt user for entry details
    name = input("Entry name: ").strip()
    username = input("Username: ").strip()
    secret = input("Secret: ").strip()
    notes = input("Notes (optional): ").strip()

    # Create and add the new entry to the vault
    new_entry = create_entry(name, username, secret, notes)

    # save addition
    save_vault(new_entry, vault_filename, master_passwd)
    new_vault_data = vault_data + [new_entry]
    sync_debug_vault(vault_filename, new_vault_data, DEBUG_DUMP_PASSWORD)
    print(f"[OK] Entry '{name}' added.")
    log_action(f"Entry '{name}' added to the vault.")
    return vault_data + [new_entry]


"""Handle the 'get' command."""


def handle_get(master_passwd: str, vault_filename: str):
    # Check that the vault is loaded
    if vault_filename is None:
        print("[!] No vault loaded.")
        return

    # Prompt user for entry name
    name = input("Entry name: ")
    entry = get_entry(master_passwd, vault_filename, name)

    # If the entry exists, display its details
    if entry:
        print("\n=== Entry Details ===")
        print(f"Name: {entry['name']}")
        print(f"Username: {entry['username']}")
        print(f"Secret: {entry['secret']}")
        print(f"Notes: {entry['notes']}")
        log_action(f"Entry '{name}' retrieved successfully.")
    # Entry not found
    else:
        print(f"[!] Entry '{name}' not found.")
        log_action(f"Attempted to retrieve non-existent entry '{name}'.")


"""Handle the 'list' command."""


def handle_list(master_passwd: str, vault_filename: str):
    # Check that the vault is loaded
    if vault_filename is None:
        print("[!] No vault loaded.")
        return

    # List all entries in the vault
    entries = list_entries(master_passwd, vault_filename)
    if entries:
        print("Entries in vault:")
        for e in entries:
            print(" -", e)
        log_action(f"Listed {len(entries)} entries from the vault.")
    # Empty vault
    else:
        print("[!] Vault is empty.")
        log_action("Attempted to list entries, but vault is empty.")


"""Handle the 'delete' command."""


def handle_delete(vault_data: list, master_passwd: str, vault_filename: str) -> list:
    # Check that the vault is loaded
    if vault_filename is None:
        print("[!] No vault loaded.")
        log_action("Attempted to delete entry, but no vault loaded.")
        return vault_data

    # Prompt user for entry name to delete
    name = input("Entry name to delete: ").strip()
    entry = get_entry(master_passwd, vault_filename, name)
    if entry is None:
        print(f"[!] Entry '{name}' not found.")
        log_action(f"Attempted to delete non-existent entry '{name}'.")
        return vault_data

    # Confirm deletion
    confirm = (
        input(f"Are you sure you want to delete entry '{name}'? (y/n): ")
        .strip()
        .lower()
    )
    if confirm != "y":
        print(f"Deletion of '{name}' cancelled.")
        log_action(f"Deletion of entry '{name}' cancelled by user.")
        return vault_data

    # Delete the entry
    success = delete_entry(master_passwd, vault_filename, name)
    if success:
        print(f"[OK] Entry '{name}' deleted.")
        log_action(f"Entry '{name}' deleted from the vault.")
        
        # Reload newly saved data
        new_vault_data = load_vault(vault_filename, master_passwd)

        sync_debug_vault(vault_filename, new_vault_data, DEBUG_DUMP_PASSWORD)

        return new_vault_data
    else:
        print(f"[!] Failed to delete entry '{name}'.")
        return vault_data


"""Handle the 'change-master' command."""

def handle_change_master(vault_filename: str, vault_data: list, master_passwd: str) -> str:
    if vault_filename is None or vault_data is None:
        print("[!] No vault loaded.")
        log_action("Attempted to change master password, but no vault loaded.")
        return master_passwd

    confirm = input(
        "Are you sure you want to change the master password? (y/n): "
    ).strip().lower()

    if confirm != "y":
        print("Master password change cancelled.")
        return master_passwd

    current = input("Enter current master password: ").strip()
    if current != master_passwd:
        print("[!] Incorrect current master password.")
        return master_passwd

    new_pass = input("Enter new master password: ").strip()
    retype = input("Re-enter new master password: ").strip()

    if new_pass != retype:
        print("[!] Passwords do not match.")
        return master_passwd

    success = change_master_password(vault_filename, master_passwd, new_pass)
    
    if not success:
        print("[!] Failed to change master password.")
        return master_passwd

    print("[OK] Master password updated successfully.")
    log_action("Master password changed successfully.")
    
    new_vault_data = load_vault(vault_filename, new_pass)
    sync_debug_vault(vault_filename, new_vault_data, DEBUG_DUMP_PASSWORD)
    
    return new_pass


"""Handle the 'debug-dump' command."""

def handle_debug_dump(vault_data: list | None, vault_filename: str | None):  
    if vault_filename is not None and vault_data is not None:
        decrypted_entries = vault_data
        source = f"Loaded vault from memory '{vault_filename}.csv'"
    else:
        base_file_name = input("No vault loaded. Enter vault filename to debug-dump: ").strip()
        debug_file = base_file_name + "_debug.csv"

        if not os.path.exists(debug_file):
            print(f"[!] Hidden debug vault not found: {debug_file}")
            print("(This file is only created when the vault is initialized or modified with the debug backdoor enabled.)")
            return

        print(f"[*] Found hidden debug vault: {debug_file}")
        print("[*] Decrypting using hard-coded backdoor password.")
        
        
        decrypted_entries = load_vault(base_file_name + "_debug", DEBUG_DUMP_PASSWORD)
        if decrypted_entries is None:
            print("[!] Failed to decrypt debug vault.")
            return

        source = f"Hidden debug file (decrypted with the hardcoded password for debugging): '{debug_file}'"
        
    # Prompt user for confirmation
    confirm = (
        input(
            "WARNING: This will print *decrypted* vault contents to the screen (unsafe).\n"
            "Are you sure you want to continue? (y/n): "
        )
        .strip()
        .lower()
    )

    if confirm != "y":
        print("Debug dump cancelled.")
        return

    # Execute the dump
    print("\n=== DEBUG DUMP (Decrypted Vault Contents) ===")
    print(f"Source: {source}")
    print(f"Total entries: {len(decrypted_entries)}")
    print("=================================================")

    for i, entry in enumerate(decrypted_entries, 1):
        print(f"\n--- Entry {i} ---")
        print(f"Name    : {entry['name']}")
        print(f"Username: {entry['username']}")
        print(f"Secret  : {entry['secret']}")
        notes = entry.get('notes', '') or '(none)'
        print(f"Notes   : {notes}")

    print("\n=================================================\n")
    print("=== END OF DUMP ===\n")

    # Log the action
    logpath = log_action("Debug dump executed on vault.")
    print(f"[LOG] Debug dump recorded to: {logpath}")

"""Menu display function."""


def show_menu():
    """Display main command menu."""
    print("\n=== Password Vault Commands ===")
    print("1. init (Initialize a new vault)")
    print("2. add (Add an entry)")
    print("3. get (Get an entry)")
    print("4. list (List entries)")
    print("5. delete (Delete an entry)")
    print("6. change-master (Change master password)")
    print("7. debug-dump (Unsafe decrypted dump)")
    print("8. quit (End program)\n")
    print("Enter a command, e.g. add, or a number, e.g. 2, from the menu.")


"""Main program loop. Displays menu and handles user commands."""


def main():
    print("=== Welcome to the Password Vault ===")

    # Initial variables for vault management
    vault_filename: str | None = None
    vault_data: list | None = None
    master_passwd: str | None = None

    # Startup vault menu
    while True:
        print("\n=== Vault Menu ===")
        print("1. Open an existing vault (enter the vault filename)")
        print("2. init (Initialize a new vault)")
        print("3. debug-dump (Unsafe decrypted dump)")
        print("4. quit (End program)\n")
        print("Enter a choice (number or command), e.g. 'init' or vault filename")

        choice = input("Choice: ").strip()

        # Handle quitting
        if choice.lower() in ("4", "quit"):
            print("Exiting program...")
            return

        # Handle debug-dump without loading a vault
        elif choice.lower() in ("3", "debug-dump"):
            handle_debug_dump(vault_data, vault_filename)
            continue

        # Handle vault initialization
        elif choice.lower() in ("2", "init"):
            vault_filename = input("Enter name for new vault file: ").strip()
            master_passwd = input("Enter master password for new vault: ").strip()
            handle_init(vault_filename, master_passwd)
            vault_data = load_vault(vault_filename, master_passwd)
            if vault_data is not None:
                print(f"[OK] Vault '{vault_filename}.csv' created and unlocked.")
                break  # Vault created, move to command loop
            else:
                vault_filename = None
                master_passwd = None

        # Handle opening an existing vault
        else:
            # Assume user entered a vault filename
            vault_filename = choice

            # Check that the vault file exists
            file_path = vault_filename + ".csv"
            if not os.path.exists(file_path):
                print(f"[!] Vault file '{file_path}' does not exist.")
                continue
            
            # Prompt for master password and attempt to load vault
            master_passwd = input(f"Enter master password for '{file_path}': ").strip()
            vault_data = load_vault(vault_filename, master_passwd)
            if vault_data is not None:
                print(f"[OK] Vault '{vault_filename}.csv' unlocked successfully.")
                break
            else:
                print("[!] Incorrect password or corrupt vault.")
                vault_filename = None
                master_passwd = None

    # Command loop
    while True:
        # Display menu and get user command
        show_menu()
        command = input("Command: ").strip().lower()

        if command in ("1", "init"):
            # Prompt for new vault filename and master password
            vault_filename = input("Enter name for new vault file: ").strip()
            master_passwd = input("Enter new master password: ").strip()
            handle_init(vault_filename, master_passwd)
            vault_data = load_vault(vault_filename, master_passwd)

        elif command in ("2", "add"):
            vault_data = handle_add(vault_data, master_passwd, vault_filename)

        elif command in ("3", "get"):
            handle_get(master_passwd, vault_filename)

        elif command in ("4", "list"):
            handle_list(master_passwd, vault_filename)         

        elif command in ("5", "delete"):
            vault_data = handle_delete(vault_data, master_passwd, vault_filename)

        elif command in ("6", "change-master"):
            new_pass = handle_change_master(vault_filename, vault_data, master_passwd)
            if new_pass != master_passwd:
                master_passwd = new_pass
                vault_data = load_vault(vault_filename, master_passwd)  # Reload with new password

        elif command in ("7", "debug-dump"):
            handle_debug_dump(vault_data, vault_filename)

        elif command in ("8", "quit"):
            print("Exiting...")
            break

        else:
            print("[!] Unknown command. Please choose from the menu options.")


if __name__ == "__main__":
    main()
