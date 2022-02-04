# SCC.439_Assignment

## Instructions
1. On the SCC.439 VM, open 2 Terminals and type this to each: `source /opt/venv-scc-439/bin/activate` to activate the Python Virtual Environment.
2. Run `python main.py` on each terminal.

    Steps:
    1. Show Welcome message. If no public/private keys, then generate them. If no encrypted directory file, generate it.
    2. Ask the user to select themself.
    3. Ask the user to select a user they want to send messages to.
    4. If the user types something, then do DH key exchange and CHAP. When finished, the user can send messages.
    5. If the user types 'close()', close the server socket and ask the user to select a new user to send messages to.
    6. back to step 3.

## Directory Structure
```
SCC.439_Assignment:
│  main.py                          # Main Entrance
│  readme.txt                       # Vulnerability document
│
├─connect
│      client.py                    # Main Client File
│      server.py                    # Main Server File
│
├─files
│      encrypted_directory.bin      # Encrypted User Directory File
│      private_key.pem              # Private Key File
│      public_key.pem               # Public Key File
│      secure_log.log               # Log file with Encrypted messages and HMACs
│
├─mycryptolib
│      directory_protection.py      # Functions to protect the Encrypted User Directory File
│      lancs_DH.py                  # Library provided by Dan
│
└─utils
        basic_functions.py          # Some essential functions
        config.py                   # Welcome messages and configuration info. Including Log Key
        secure_logging.py           # Main Logging file
```

## Vulnerabilities
1. Buffer Overflow Attack occurs when a user tries to send a large message at once. This can lead to hackers trying to get information that shouldn't be displayed in the first place. It is even possible to steal the key from memory.
2. The public key and the private key should be stored securely. Failing to manage these keys can lead to severe data leakage. Using key management hardware to store these keys may be a solution.
3. Log Password and Log key in config.py should be stored securely. Failed to manage the password and the key, hackers can calculate the enc_key and iv very easily. Thus, all messages in the log file can be decrypted.
4. Some exceptions failed to be handled because of the time limit. Exceptions during program operation can weaken the availability of the program.
5. In the very unlikely event that a CRC may collide This means that two different strings generate the same CRC. This means that it is not possible to identify whether information has been tampered with during transmission.
6. If the client requests the server in large numbers, it may cause a denial-of-service attack. Because the server will calculate all the keys at once, which will consume system resources.
7. A more secure method should be used when generating user lists as encrypted directories. For convenience, this program is written directly in a python file (see directory_protection.py). If the python file is stolen, the encryption is invalid.