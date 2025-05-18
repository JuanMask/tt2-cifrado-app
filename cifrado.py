import os
import json
import base64
import secrets
import concurrent.futures
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import re

# Contraseñas comunes a evitar
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "qwerty", "12345678", "111111", "123123",
    "abc123", "12345", "password1", "admin", "1234"
}

def is_valid_password(pw: str) -> bool:
    if len(pw) < 8:
        raise ValueError("❌ La contraseña debe tener al menos 8 caracteres.")
    if pw.lower() in COMMON_PASSWORDS:
        raise ValueError("❌ La contraseña es demasiado común. Usa una más segura.")
    if not re.search(r"[a-z]", pw):
        raise ValueError("❌ La contraseña debe contener al menos una letra minúscula.")
    if not re.search(r"[A-Z]", pw):
        raise ValueError("❌ La contraseña debe contener al menos una letra mayúscula.")
    if not re.search(r"\d", pw):
        raise ValueError("❌ La contraseña debe contener al menos un número.")
    if not re.search(r"[!@#$%]", pw):
        raise ValueError("❌ La contraseña debe contener al menos un carácter especial (! @ # $ %).")
    return True

def cargar_salt(salt_file_path):
    try:
        with open(salt_file_path, "r") as f:
            salt_data = json.load(f)
        return base64.b64decode(salt_data["salt"])
    except FileNotFoundError:
        raise FileNotFoundError("❌ El archivo salt.json no existe. Debes crearlo primero con un salt válido.")
    except Exception as e:
        raise ValueError(f"❌ Error al cargar el salt: {e}")

def cifrar_archivos(file_paths, password, output_folder, salt_file_path):
    # Validar contraseña
    is_valid_password(password)
    
    # Cargar salt
    salt = cargar_salt(salt_file_path)
    
    # Derivar clave
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    def cifrar_archivo(file_path):
        try:
            # Generar IV único para cada archivo
            iv = secrets.token_bytes(12)
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            # Leer archivo original
            with open(file_path, "rb") as f:
                plaintext = f.read()

            # Cifrar contenido
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            encrypted_data = iv + encryptor.tag + ciphertext
            encrypted_b64 = base64.b64encode(encrypted_data)

            # Guardar archivo cifrado
            filename = os.path.basename(file_path) + ".enc"
            encrypted_file_path = os.path.join(output_folder, filename)
            with open(encrypted_file_path, "wb") as f:
                f.write(encrypted_b64)

        except Exception as e:
            raise Exception(f"[✘] Error cifrando {file_path}: {e}")

    # Cifrado en paralelo
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(cifrar_archivo, file_paths)