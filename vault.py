import os
import base64
import json
from cryptography.exceptions import InvalidKey
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


SALT_FILENAME = "salt.bin"
RAW_KEY_FILENAME = "key.bin"
VAULT_FILENAME = "vault.json.enc"

def read_salt_file_line(file_name: str) -> str:
    try:
        file = open(file_name, "rb")
    except FileNotFoundError:
        open(file_name, "w").close()
        return b''

    line = file.readline()
    file.close()
    
    return line


def is_empty_file(file_name: str) -> bool:
    line = read_salt_file_line(file_name)
    return line == b'' 

def get_password_in_bytes() -> bytes:
    return input().encode()
    
def generate_salt() -> bytes:
    return os.urandom(16)

def save_salt(salt: bytes) -> None:
    with open(SALT_FILENAME, 'wb') as file:
        file.write(salt)


def read_salt() -> bytes:
    try:
        with open(SALT_FILENAME, 'rb') as file:
            salt = file.read()
    except FileNotFoundError:
        print(f"{SALT_FILENAME} was not found.")
        return b''

    return salt


def generate_key_derivation_function(salt: bytes) -> PBKDF2HMAC:
    return PBKDF2HMAC(
        algorithm = hashes.SHA256(), 
        length = 32,
        salt = salt,
        iterations = 1_200_000
    )



def derive_password(password: bytes, salt: bytes):
    kdf = generate_key_derivation_function(salt)
    return kdf.derive(password)

def verify_password(salt: bytes, raw_key: bytes, password: bytes) -> bool:
    kdf = generate_key_derivation_function(salt)
    try:
        kdf.verify(password, raw_key)
    except InvalidKey:
        return False
    return True
        

def save_raw_key(raw_key: bytes):
    with open(RAW_KEY_FILENAME, 'wb') as file:
        file.write(raw_key)

def read_raw_key() -> bytes:
    try:
        with open(RAW_KEY_FILENAME, 'rb') as file:
            raw_key = file.read()
    except FileNotFoundError:
        print(f"{RAW_KEY_FILENAME} was not found.")
        return b''

    return raw_key
    

def get_secret_data() -> dict:
    tag = input("tag: ")
    user = input("user/email: ")
    password = input("password: ")
    return {tag : {"user": user, "password": password} }


def add_new_secret(secrets: dict, new_secret: dict):
    secrets.update(new_secret)


def read_secrets_from_vault(fernet: Fernet) -> dict:
    try:
        with open(VAULT_FILENAME, "rb") as vault:
            encrypted_data = vault.read()
    except FileNotFoundError:
        return {}

    if encrypted_data == b'': 
        return {}

    decrypted_data = fernet.decrypt(encrypted_data)
    secrets = json.loads(decrypted_data.decode())

    return secrets

def update_vault(new_secret: bytes):
    with open(VAULT_FILENAME, 'wb') as vault:
        vault.write(new_secret)
        

    


def add_secret_to_vault(fernet: Fernet):
    new_secret = get_secret_data()
    secrets = read_secrets_from_vault(fernet)
    
    add_new_secret(secrets, new_secret)

    json_data = json.dumps(secrets).encode()
    encrypted_data = fernet.encrypt(json_data)
    update_vault(encrypted_data)

    print("Secret added successfully.")
  


def show_vault_secrets(fernet: Fernet):
    secrets = read_secrets_from_vault(fernet)
    if not secrets:
        print("Vault is empty.")
        return
    
    for tag, info in secrets.items():
        print(f"Tag: {tag}")
        print(f" User: {info['user']}")
        print(f" Password: {info['password']}\n")

def initialize_menu_options():
    return {
        "1": add_secret_to_vault, 
        "2": show_vault_secrets,
    }


def initialize_password_and_keys():
    print("Create a new password\n")
    password = get_password_in_bytes()
    salt = generate_salt()
    save_salt(salt)
    raw_key = derive_password(password, salt)
    save_raw_key(raw_key)
    return password, salt, raw_key

def load_existing_password_and_keys():
    password = get_password_in_bytes()
    salt = read_salt()
    raw_key = read_raw_key()
    return password, salt, raw_key

def print_options():
    print("\nSelect an option or enter 'exit' to close: \n")
    print("1 - Add a new secret to the vault. \n")
    print("2 - Show all secrets from the vault. \n")

def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')



def main():
    print("\nWelcome to The Vault\n")
   
    if is_empty_file(SALT_FILENAME) and is_empty_file(RAW_KEY_FILENAME):
        print("Create the main password to access or 'exit' to close the program.\n")
        password, salt, raw_key = initialize_password_and_keys()
    else:
        print("Enter the main password to access or 'exit' to close the program.\n")
        password, salt, raw_key = load_existing_password_and_keys()

    if not verify_password(salt, raw_key, password):
        exit()

    clear_terminal()

    options = initialize_menu_options()

    fernet_key = base64.urlsafe_b64encode(raw_key)
    fernet = Fernet(fernet_key)

    print_options()
    user_entry = input()

    while user_entry.lower() != "exit":
        options[user_entry](fernet)
        print_options()
        user_entry = input()



if __name__ == '__main__':
    main()







