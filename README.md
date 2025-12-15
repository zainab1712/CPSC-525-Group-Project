# CPSC525GroupProject
*CPSC 525 F25 Group Project*

*CWE-215: Insecure Exposure of Sensitive Information to an Unauthorized Actor*


*Jahnissi Nwakanma - 30174827*

*Khadeeja Abbas - 30180776*

*Shanza Raza - 30192765*

*Zainab Bari - 30154224*

---

- High level description of your code and exploit:

  This code implmented a CLI-vault generator. These vaults are supposed to store the user's private information, encrypting the contents with AES encryption. However, the developers decided to create a debugging version of the vault for testing and forgot to fully remove this option from the login screen. If the         attacker knows the name of the vault, they can then get all the contents of it without logging in. How horrible.
  
- How and where to compile/run your code:

  To compile to CLI-application, run `python main.py`

  From here, you will see the text that will guide you through our program

- How and where to compile/run your exploit:

  To run the exploit code, run `python exploit.py`

  This will generate a new vault, encrypt it, then use the exploit to output the contents without needing the password
