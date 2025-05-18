import os
import json
import base64
import concurrent.futures
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import shutil

def cargar_salt(salt_file_path):
    try:
        with open(salt_file_path, "r") as f:
            salt_data = json.load(f)
        return base64.b64decode(salt_data["salt"])
    except FileNotFoundError:
        raise FileNotFoundError("❌ El archivo salt.json no existe.")
    except Exception as e:
        raise ValueError(f"❌ Error al cargar el salt: {e}")

def descifrar_archivos(password, input_folder, output_folder, salt_file_path):
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

    # Obtener lista de archivos cifrados
    encrypted_files = [f for f in os.listdir(input_folder) if f.endswith('.enc')]
    if not encrypted_files:
        raise ValueError("No hay archivos cifrados para descifrar")

    # Probar con el primer archivo para validar contraseña
    test_file = os.path.join(input_folder, encrypted_files[0])
    try:
        with open(test_file, "rb") as f:
            encrypted_b64 = f.read()
        encrypted_data = base64.b64decode(encrypted_b64)

        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        _ = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception:
        raise ValueError("❌ ERROR AL DESCIFRAR, CONTRASEÑA INCORRECTA")

    # Función para descifrar un archivo
    def descifrar_archivo(encrypted_file):
        try:
            with open(os.path.join(input_folder, encrypted_file), "rb") as f:
                encrypted_b64 = f.read()
            encrypted_data = base64.b64decode(encrypted_b64)

            iv = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]

            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Guardar archivo descifrado
            output_filename = encrypted_file[:-4]  # Quitar .enc
            output_path = os.path.join(output_folder, output_filename)
            with open(output_path, "wb") as f:
                f.write(plaintext)

        except Exception as e:
            raise Exception(f"[✘] Error descifrando {encrypted_file}: {e}")

    # Descifrado en paralelo
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(descifrar_archivo, encrypted_files)

