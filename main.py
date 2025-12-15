"""
CPSC 525 F25 Group Project
CWE-215: Insecure Exposure of Sensitive Information to an Unauthorized Actor

Jahnissi Nwakanma - 30174827
Khadeeja Abbas - 30180776
Shanza Raza - 30192765
Zainab Bari - 30154224


main.py
Handles the different commands and their functionalities.
"""

import datetime
from vault import (
    init_vault,
    load_vault,
    save_vault,
    change_master_password,
    sync_debug_vault,
)
from entries import create_entry, delete_entry, get_entry, list_entries
import os

# https://docs.python.org/3/library/pickle.html
import pickle
import secrets
import string

DEBUG_DUMP_PASSWORD = "debugdump123"

"""Append a timestamped message to logfile.
Returns the full path to the logfile."""


def log_action(message: str, logfile: str = "vault.log"):
    try:
        now = datetime.datetime.now()

        ts = now.isoformat(sep="T", timespec="auto") + "Z"
        entry = f"{ts} - {message}\n"
        with open(logfile, "a", encoding="utf-8") as f:
            f.write(entry)
        return os.path.abspath(logfile)
    except Exception as e:
        print(f"Failed to log action: {e}")
        log_action(f"Failed to log action '{e}'.")
        raise


"""Handle the 'init' command."""


def handle_init(vault_filename: str, master_passwd: str) -> str:
    try:
        # Initialize a new vault with the given master password
        init_vault(vault_filename, master_passwd)
    except Exception as e:
        print(f"Failed to initalize vault: {vault_filename}")
        log_action(f"Failed to initalize vault '{vault_filename}'.")
        raise

    # Store the master password as a vault entry
    master_entry = create_entry(
        name="__MASTER_PASSWORD__",
        username="__MASTER__",
        secret=master_passwd,
        notes=f"Automatically stored master password for '{vault_filename}'.csv",
    )

    try:
        # Save the vault
        save_vault(master_entry, vault_filename, master_passwd)
        sync_debug_vault(vault_filename, [master_entry], DEBUG_DUMP_PASSWORD)
        print("[OK] Vault initialized.")
        log_action(
            "Vault initialized successfully and master password stored as entry."
        )
        return vault_filename
    except Exception as e:
        print(f"Failed to initalize vault: {vault_filename}")
        log_action(f"Failed to initalize vault '{vault_filename}'.")
        raise


"""Handle the 'add' command."""


def handle_add(
    vault_data: list, master_passwd: str, vault_filename: str
) -> list:  # Check that the vault is loaded
    try:
        # if vault_data is None or vault_filename is None:
        if vault_filename is None:
            print("[!] No vault loaded.")
            return vault_data

        # Prompt user for entry details
        name = input("Entry name: ").strip()
        username = input("Username: ").strip()

        secret_choice = input(
            "Secret: (press Enter to generate strong password) "
        ).strip()
        if not secret_choice:
            print("Generating password...")
            secret = handle_generate()  # Returns the final password
            if not secret:
                print("[!] Password generation cancelled.")
                return vault_data
        else:
            secret = secret_choice

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
    except Exception as e:
        print(f"Failed to add to vault: {vault_filename}")
        log_action(f"Failed to add to vault '{vault_filename}'.")
        raise


"""Handle the 'generate' command."""


def handle_generate():
    print("\n=== Password Generator ===")
    try:
        # Ask for length with validation
        while True:
            length_input = input(
                "How many characters long? (default 20, min 12, max 128): "
            ).strip()
            if not length_input:
                length = 20
                break
            try:
                length = int(length_input)
                if length < 12:
                    print(
                        "[!] Password too short, minimum recommended is 12. Using 12."
                    )
                    length = 12
                elif length > 128:
                    print("[!] Password too long, maximum is 128. Using 128.")
                    length = 128
                break
            except ValueError:
                print("[!] Please enter a valid number.")

        # Character set options
        print(
            "\nInclude these character types? (y/n for each) (all will be included by default if none selected)"
        )

        choice = ""
        while choice != "y" and choice != "n":
            choice = input("  Uppercase letters (A-Z)? (y/n): ").strip().lower()
            if choice != "y" and choice != "n":
                print("[!] Invalid choice — please type 'y' or 'n'.")
            else:
                use_upper = choice == "y"

        choice = ""
        while choice != "y" and choice != "n":
            choice = input("  Lowercase letters (a-z)? (y/n): ").strip().lower()
            if choice != "y" and choice != "n":
                print("[!] Invalid choice — please type 'y' or 'n'.")
            else:
                use_lower = choice == "y"

        choice = ""
        while choice != "y" and choice != "n":
            choice = input("  Digits (0-9)? (y/n): ").strip().lower()
            if choice != "y" and choice != "n":
                print("[!] Invalid choice — please type 'y' or 'n'.")
            else:
                use_digits = choice == "y"

        choice = ""
        while choice != "y" and choice != "n":
            choice = input("  Symbols (!@#$%^&* etc.)? (y/n): ").strip().lower()
            if choice != "y" and choice != "n":
                print("[!] Invalid choice — please type 'y' or 'n'.")
            else:
                use_symbols = choice == "y"

        # Select all if user does not choose any
        if not (use_upper or use_lower or use_digits or use_symbols):
            print("[!] No character types selected, enabling all for security.")
            use_upper = use_lower = use_digits = use_symbols = True

        while True:

            # Generate the password
            password = generate_password(
                length=length,
                include_uppercase=use_upper,
                include_lowercase=use_lower,
                include_digits=use_digits,
                include_symbols=use_symbols,
            )
            print("\nGenerated Password:")
            print(password)
            log_action(
                f"[LOG] Generated random password: length={len(password)}, upper={use_upper}, lower={use_lower}, digits={use_digits}, symbols={use_symbols}"
            )

            while True:
                confirm = (
                    input(
                        "\nUse this password? (y = yes, n = no, r = regenerate new one): "
                    )
                    .strip()
                    .lower()
                )

                # Accept the generated password
                if confirm == "y":
                    return password

                # Generate a new password
                elif confirm == "r":
                    break

                # Manually enter a password or retry generation
                elif confirm == "n":
                    choice = (
                        input(
                            "Do you want to (r)egenerate or (m)anually enter a password? (r/m): "
                        )
                        .strip()
                        .lower()
                    )
                    if choice == "r":
                        break
                    elif choice == "m":
                        manual = input("Enter your own password: ").strip()
                        if manual:
                            return manual
                        else:
                            print("[!] Password cannot be empty. Try again.")
                    else:
                        print("[!] Invalid choice — please type 'r' or 'm'.")

                else:
                    print("[!] Invalid choice — please type 'y', 'n', or 'r'.")
    except Exception as e:
        print(f"Failed to generate password: {e}")
        log_action(f"Failed to generate password '{e}'.")
        raise


"""Handle the 'get' command."""


def handle_get(master_passwd: str, vault_filename: str):
    try:
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
    except Exception as e:
        print(f"Failed to get vault contents: {e}")
        log_action(f"Failed to get vault contents: '{e}'.")
        raise


"""Handle the 'list' command."""


def handle_list(master_passwd: str, vault_filename: str):
    try:
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
    except Exception as e:
        print(f"Failed to list vault contents: {e}")
        log_action(f"Failed to list vault contents: '{e}'.")
        raise


"""Handle the 'delete' command."""


def handle_delete(vault_data: list, master_passwd: str, vault_filename: str) -> list:
    try:
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
    except Exception as e:
        print(f"Failed to delete vault entry: {e}")
        log_action(f"Failed to delete vault entry: '{e}'.")
        raise


"""Handle the 'edit' command."""


def handle_edit(
    vault_data: list, master_passwd: str, vault_filename: str
) -> list:  # Edit the vault
    try:
        # if vault_data is None or vault_filename is None:
        if vault_filename is None:

            print("[!] No vault loaded.")
            return vault_data

        # Prompt user for entry details
        name = input("Entry name: ").strip()
        entry = get_entry(master_passwd, vault_filename, name)

        if entry:
            try:
                # ask for changes for the name
                choice = ""
                while choice != "y" and choice != "n":
                    choice = input("  Edit the name? (y/n): ").strip().lower()
                    if choice != "y" and choice != "n":
                        print("[!] Invalid choice — please type 'y' or 'n'.")
                    else:
                        edit_name = choice == "y"

                if edit_name:
                    name_change = input("  Input change: ").strip().lower()
                else:
                    name_change = entry["name"]

                # ask for changes for the username
                choice = ""
                while choice != "y" and choice != "n":
                    choice = input("  Edit the username? (y/n): ").strip().lower()
                    if choice != "y" and choice != "n":
                        print("[!] Invalid choice — please type 'y' or 'n'.")
                    else:
                        edit_username = choice == "y"

                if edit_username:
                    username_change = input("  Input change: ").strip().lower()
                else:
                    username_change = entry["username"]

                # ask for changes for the username
                choice = ""
                while choice != "y" and choice != "n":
                    choice = input("  Edit the secret? (y/n): ").strip().lower()
                    if choice != "y" and choice != "n":
                        print("[!] Invalid choice — please type 'y' or 'n'.")
                    else:
                        edit_secret = choice == "y"

                if edit_secret:
                    secret_change = input("  Input change: ").strip().lower()
                else:
                    secret_change = entry["secret"]

                # ask for changes for the notes
                choice = ""
                while choice != "y" and choice != "n":
                    choice = input("  Edit the notes? (y/n): ").strip().lower()
                    if choice != "y" and choice != "n":
                        print("[!] Invalid choice — please type 'y' or 'n'.")
                    else:
                        edit_notes = choice == "y"

                if edit_notes:
                    notes_change = input("  Input change: ").strip().lower()
                else:
                    notes_change = entry["notes"]

                # creating a new dictionary to replace the old entry
                changed_entry = create_entry(
                    name_change, username_change, secret_change, notes_change
                )

                # delete the old entry
                delete_entry(master_passwd, vault_filename, name)

                # encrypt the new data
                save_vault(changed_entry, vault_filename, master_passwd)

                #do the same for the debug file
                new_vault_data = load_vault(vault_filename, master_passwd)
                sync_debug_vault(vault_filename, new_vault_data, DEBUG_DUMP_PASSWORD)

                return
            except FileNotFoundError:
                print(f"[!] Vault file '{vault_file_name}' not found.")
                log_action(f"Failed to find entry '{name}'.")

                return None
            except Exception as e:
                print(f"Failed to edit vault: {e}")
                log_action(f"Failed to edit entry '{name}'.")
                raise
        else:
            print(f"[!] Entry '{name}' not found.")
            log_action(f"Attempted to retrieve non-existent entry '{name}'.")
    except Exception as e:
        print(f"Failed to edit vault contents: {e}")
        log_action(f"Failed to edit vault contents: '{e}'.")
        raise


"""Handle the 'change-master' command."""


def handle_change_master(
    vault_filename: str, vault_data: list, master_passwd: str
) -> str:
    try:
        # if vault_filename is None or vault_data is None:
        if vault_filename is None:
            print("[!] No vault loaded.")
            log_action("Attempted to change master password, but no vault loaded.")
            return master_passwd

        confirm = (
            input("Are you sure you want to change the master password? (y/n): ")
            .strip()
            .lower()
        )

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
    except Exception as e:
        print(f"Failed to change master password: {e}")
        log_action(f"Failed to change master password: '{e}'.")
        raise


"""Handle the 'debug-dump' command."""


def handle_debug_dump(vault_data: list | None, vault_filename: str | None):
    try:
        if vault_filename is not None and vault_data is not None:
            decrypted_entries = vault_data
            source = f"Loaded vault from memory '{vault_filename}.csv'"
        else:
            base_file_name = input(
                "No vault loaded. Enter vault filename to debug-dump: "
            ).strip()
            debug_file = base_file_name + "_debug.csv"

            if not os.path.exists(debug_file):
                print(f"[!] Hidden debug vault not found: {debug_file}")
                print(
                    "(This file is only created when the vault is initialized or modified with the debug backdoor enabled.)"
                )
                return

            print(f"[*] Found hidden debug vault: {debug_file}")
            print("[*] Decrypting using hard-coded backdoor password.")

            decrypted_entries = load_vault(
                base_file_name + "_debug", DEBUG_DUMP_PASSWORD
            )
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
            notes = entry.get("notes", "") or "(none)"
            print(f"Notes   : {notes}")

        print("\n=================================================\n")
        print("=== END OF DUMP ===\n")

        # Log the action
        logpath = log_action("Debug dump executed on vault.")
        print(f"[LOG] Debug dump recorded to: {logpath}")

    except Exception as e:
        print(f"Failed to debug dump: {e}")
        log_action(f"Failed to debug dump: '{e}'.")
        raise


def generate_password(
    length=20,
    include_uppercase=True,
    include_lowercase=True,
    include_digits=True,
    include_symbols=True,
) -> str:

    # Define the password alphabet
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    password_alphabet = ""
    user_choice = []

    if include_lowercase:
        password_alphabet += lowercase
        user_choice.append(secrets.choice(lowercase))
    if include_uppercase:
        password_alphabet += uppercase
        user_choice.append(secrets.choice(uppercase))
    if include_digits:
        password_alphabet += digits
        user_choice.append(secrets.choice(digits))
    if include_symbols:
        password_alphabet += symbols
        user_choice.append(secrets.choice(symbols))

    # Fallback if no character types selected (even though this is checked in handle_generate)
    if not password_alphabet:
        password_alphabet = lowercase + uppercase + digits + symbols
        user_choice = [secrets.choice(password_alphabet)]

    # Build the password, making sure to include at least one of each category selected
    password_chars = user_choice[:]
    for _ in range(length - len(user_choice)):
        password_chars.append(secrets.choice(password_alphabet))

    # Shuffle it so that the user_choice characters are not all at the start
    secrets.SystemRandom().shuffle(password_chars)

    # Return the final password
    return "".join(password_chars)


"""Menu display function."""


def show_menu():
    """Display main command menu."""
    print("\n=== Password Vault Commands ===")
    print("1. init (Initialize a new vault)")
    print("2. add (Add an entry)")
    print("3. generate (Generate a strong random password)")
    print("4. get (Get an entry)")
    print("5. list (List entries)")
    print("6. delete (Delete an entry)")
    print("7. edit (Edit an entry)")
    print("8. change-master (Change master password)")
    print("9. debug-dump (Unsafe decrypted dump)")
    print("10. quit (End program)\n")
    print("Enter a command, e.g. add, or a number, e.g. 2, from the menu.")


"""Main program loop. Displays menu and handles user commands."""


def main():
    try:
        print("=== Welcome to the Password Vault ===")

        # Initial variables for vault management
        vault_filename: str | None = None
        vault_data: list | None = None
        master_passwd: str | None = None

        # Startup vault menu
        while True:
            try:
                print("\n=== Vault Menu ===")
                print("1. Open an existing vault (enter the vault filename)")
                print("2. init (Initialize a new vault)")
                print("3. debug-dump (Unsafe decrypted dump)")
                print("4. quit (End program)\n")
                print(
                    "Enter a choice (number or command), e.g. 'init' or vault filename"
                )

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
                    master_passwd = input(
                        "Enter master password for new vault: "
                    ).strip()
                    handle_init(vault_filename, master_passwd)
                    vault_data = load_vault(vault_filename, master_passwd)
                    if vault_data is not None:
                        print(
                            f"[OK] Vault '{vault_filename}.csv' created and unlocked."
                        )
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
                    master_passwd = input(
                        f"Enter master password for '{file_path}': "
                    ).strip()
                    vault_data = load_vault(vault_filename, master_passwd)
                    if vault_data is not None:
                        print(
                            f"[OK] Vault '{vault_filename}.csv' unlocked successfully."
                        )
                        break
                    else:
                        print("[!] Incorrect password or corrupt vault.")
                        vault_filename = None
                        master_passwd = None
            except EOFError:
                print("No more input so exiting")
                print("Exiting program...")
                return
        # Command loop
        while True:
            try:
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

                elif command in ("3", "generate"):
                    handle_generate()

                elif command in ("4", "get"):
                    handle_get(master_passwd, vault_filename)

                elif command in ("5", "list"):
                    handle_list(master_passwd, vault_filename)

                elif command in ("6", "delete"):
                    vault_data = handle_delete(
                        vault_data, master_passwd, vault_filename
                    )

                elif command in ("7", "edit"):
                    vault_data = handle_edit(vault_data, master_passwd, vault_filename)

                elif command in ("8", "change-master"):
                    new_pass = handle_change_master(
                        vault_filename, vault_data, master_passwd
                    )
                    if new_pass != master_passwd:
                        master_passwd = new_pass
                        vault_data = load_vault(
                            vault_filename, master_passwd
                        )  # Reload with new password

                elif command in ("9", "debug-dump"):
                    handle_debug_dump(vault_data, vault_filename)

                elif command in ("10", "quit"):
                    print("Exiting...")
                    break

                else:
                    print("[!] Unknown command. Please choose from the menu options.")
            except EOFError:
                print("No more input so exiting")
                break
    except Exception as e:
        print(f"Error in main menu: {e}")
        log_action(f"Error in main menu: '{e}'.")
        raise


if __name__ == "__main__":
    main()
