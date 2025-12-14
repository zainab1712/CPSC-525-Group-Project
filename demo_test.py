"""
CPSC 525 F25 Group Project
CWE-215: Insecure Exposure of Sensitive Information to an Unauthorized Actor

Jahnissi Nwakanma -
Khadeeja Abbas - 30180776
Shanza Raza - 30192765
Zainab Bari - 30154224


demo_test.py
Tests commands and demonstrates the CWE-215 vulnerability.
"""

import os


def test_commands():
    """Run simple tests for add/get/list/delete."""

    with open("test_commands.txt", "w") as file:
        # initalize a new vault
        file.write("2\n")
        file.write("testingVaultFile\n")
        file.write("ThePasswordForTestingVaultFile\n")

        # add an entry
        file.write("2\n")
        file.write("newEntryForTesting\n")
        file.write("newUsernameForTesting")
        file.write("\n\n")
        file.write("20\n")
        file.write("y\n")
        file.write("y\n")
        file.write("y\n")
        file.write("y\n")
        file.write("y\n")
        file.write("testingtesting123\n")

        # list
        file.write("5\n")

        # quit
        file.write("10\n")

    # try it
    os.system("python main.py < test_commands.txt")
    pass


def run_debug_demo():
    """
    Demonstrate the CWE-215 issue:
    Use the --debug-dump command to show decrypted vault contents.
    """
    with open("run_debug_demo.txt", "w") as file:
        file.write("3\n")
        # make sure the test_commands function was run before hand and utilize that file
        file.write("testingVaultFile\n")
        file.write("y\n")
        file.write("4\n")

    # try it
    os.system("python main.py < run_debug_demo.txt")
    pass


if __name__ == "__main__":
    try:
        test_commands()
        run_debug_demo()
    except Exception as e:  # pylint: disable=broad-except
        print("Exploit failed.")
        raise
