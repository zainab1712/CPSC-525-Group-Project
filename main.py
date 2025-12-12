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
from vault import init_vault, load_vault, save_vault  # , change_master_password
from entries import create_entry, delete_entry, get_entry, list_entries
import os


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


def handle_init(vault_name, master_passwd):
    # Initialize a new vault with the given master password
    vault_dict = init_vault(vault_name, master_passwd)

    # Store the master password as a vault entry
    master_entry = create_entry(
        name="__MASTER_PASSWORD__",
        username="__MASTER__",
        secret=master_passwd,
        notes="Automatically stored master password",
    )

    # Save the vault
    print("master entry: ", master_entry)
    save_vault(master_entry, vault_name, master_passwd)
    print("[OK] Vault initialized.")
    log_action("Vault initialized successfully and master password stored as entry.")
    return vault_name


"""Handle the 'add' command."""


def handle_add(vault, master_passwd):
    # Check that the vault is loaded
    if vault is None:
        print("[!] No vault loaded.")
        return vault

    print(vault)
    # Prompt user for entry details
    name = input("Entry name: ")
    username = input("Username: ")
    secret = input("Secret: ")
    notes = input("Notes (optional): ")

    # Create and add the new entry to the vault
    new_entry = create_entry(name, username, secret, notes)

    # save addition
    save_vault(new_entry, vault, master_passwd)
    print(f"[OK] Entry '{name}' added.")
    log_action(f"Entry '{name}' added to the vault.")
    return vault


"""Handle the 'get' command."""


def handle_get(master_passwd, vault):
    # Check that the vault is loaded
    if vault is None:
        print("[!] No vault loaded.")
        return

    # Prompt user for entry name
    name = input("Entry name: ")
    entry = get_entry(master_passwd, vault, name)

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


def handle_list(master_passwd, vault):
    # Check that the vault is loaded
    if vault is None:
        print("[!] No vault loaded.")
        return

    # List all entries in the vault
    entries = list_entries(master_passwd, vault)
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


def handle_delete(vault, master_passwd):
    # Check that the vault is loaded
    if vault is None:
        print("[!] No vault loaded.")
        log_action("Attempted to delete entry, but no vault loaded.")
        return vault

    # Prompt user for entry name to delete
    name = input("Entry name to delete: ")
    entry = get_entry(master_passwd, vault, name)
    if entry is None:
        print(f"[!] Entry '{name}' not found.")
        log_action(f"Attempted to delete non-existent entry '{name}'.")
        return vault

    # Confirm deletion
    confirm = (
        input(f"Are you sure you want to delete entry '{name}'? (y/n): ")
        .strip()
        .lower()
    )
    if confirm != "y":
        print(f"Deletion of '{name}' cancelled.")
        log_action(f"Deletion of entry '{name}' cancelled by user.")
        return vault

    # Delete the entry
    if delete_entry(master_passwd, vault, name):
        # save_vault(vault, master_passwd)
        print(f"[OK] Entry '{name}' deleted.")
        log_action(f"Entry '{name}' deleted from the vault.")
    return vault


"""Handle the 'change-master' command."""


def handle_change_master(vault, master_passwd):
    # # Check that the vault is loaded
    # if vault is None:
    #     print("[!] No vault loaded.")
    #     log_action("Attempted to change master password, but no vault loaded.")
    #     return master_passwd

    # # Confirm that user wants to change the master password
    # confirm = input(
    #     "Are you sure you want to change the master password? (y/n): "
    # ).strip().lower()
    # if confirm != "y":
    #     print("Master password change cancelled.")
    #     log_action("Master password change cancelled by user.")
    #     return master_passwd

    # # Prompt user for a new master password, and ask them to retype it
    # new_pass = input("Enter new master password: ").strip()
    # retype_pass = input("Re-enter new master password: ").strip()

    # # If the two inputs do not match, don't change the password
    # if new_pass != retype_pass:
    #     print("[!] Passwords do not match. Master password not changed.")
    #     log_action("Master password change failed: passwords did not match.")
    #     return master_passwd

    # # Change the master password
    # change_master_password(vault, master_passwd, new_pass)
    # print("[OK] Master password updated successfully.")
    # log_action("Master password changed successfully.")
    # return new_pass
    print("[!] Currently not implemented.")
    return master_passwd


"""Handle the 'debug-dump' command."""


def handle_debug_dump(vault):
    # If no vault is loaded, prompt for a vault file to dump
    if vault is None:
        vault_file = input(
            "No vault loaded. Enter vault filename to debug-dump: "
        ).strip()
        if not os.path.exists(vault_file):
            print(f"[!] Vault file '{vault_file}' does not exist.")
            return
        # Load vault without master password (unsafe)
        # https://docs.python.org/3/library/pickle.html
        import pickle

        try:
            with open(vault_file, "rb") as f:
                vault = pickle.load(f)
            print(
                f"[OK] Vault '{vault_file}' loaded for debug-dump (no master password)."
            )
        except Exception as e:
            print(f"[!] Failed to load vault: {e}")
            return

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
    for entry in vault.get("entries", []):
        print(f"Name: {entry.get('name')}")
        print(f"Username: {entry.get('username')}")
        print(f"Secret: {entry.get('secret')}")
        print(f"Notes: {entry.get('notes')}")
        print("-" * 40)
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
    print("Enter a command, e.g. add")


"""Main program loop. Displays menu and handles user commands."""


def main():
    print("=== Welcome to the Password Vault ===")

    # Initial variables for vault management
    vault = None
    VAULT_FILE = None
    master_passwd = None

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
            handle_debug_dump(vault)
            continue

        # Handle vault initialization
        elif choice.lower() in ("2", "init"):
            VAULT_FILE = input("Enter name for new vault file: ").strip()
            master_passwd = input("Enter master password for new vault: ").strip()
            vault = handle_init(VAULT_FILE, master_passwd)
            break  # Vault created, move to command loop

        # Handle opening an existing vault
        else:
            # Assume user entered a vault filename
            VAULT_FILE = choice

            # Check that the vault file exists
            if not os.path.exists(VAULT_FILE):
                print(f"[!] Vault file '{VAULT_FILE}' does not exist.")
                continue

            # Prompt for master password and attempt to load vault
            master_passwd = input(f"Enter master password for '{VAULT_FILE}': ").strip()
            vault = load_vault(master_passwd)
            if vault:
                print(f"[OK] Vault '{VAULT_FILE}' unlocked successfully.")
                break
            else:
                print("[!] Incorrect password or corrupt vault.")
                vault = None

    # Command loop
    while True:
        # Display menu and get user command
        show_menu()
        command = input("Command: ").strip().lower()

        if command in ("1", "init"):
            # Prompt for new vault filename and master password
            VAULT_FILE = input("Enter name for new vault file: ").strip()
            master_passwd = input("Enter new master password for this vault: ").strip()
            vault = handle_init(VAULT_FILE, master_passwd)

        elif command in ("2", "add"):
            vault = handle_add(vault, master_passwd)

        elif command in ("3", "get"):
            master_passwd = input("Enter the password for this vault: ").strip()
            handle_get(master_passwd, vault)

        elif command in ("4", "list"):
            master_passwd = input("Enter the password for this vault: ").strip()
            handle_list(master_passwd, vault)

        elif command in ("5", "delete"):
            vault = handle_delete(vault, master_passwd)

        elif command in ("6", "change-master"):
            master_passwd = handle_change_master(vault, master_passwd)

        elif command in ("8", "quit"):
            print("Saving vault and exiting...")
            if vault:
                save_vault(vault, master_passwd)
                break
            else:
                print("No vault to save. Exiting.")
                break

        else:
            print("[!] Unknown command. Please choose from the menu options.")


if __name__ == "__main__":
    main()
