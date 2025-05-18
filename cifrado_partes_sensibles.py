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



# Añadir al inicio del archivo
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "qwerty", "12345678", "111111", "123123",
    "abc123", "12345", "password1", "admin", "1234"
}

def is_valid_password(password):
    """Valida que la contraseña cumpla con los requisitos"""
    if len(password) < 8:
        raise ValueError("La contraseña debe tener al menos 8 caracteres")
    if password.lower() in COMMON_PASSWORDS:
        raise ValueError("La contraseña es demasiado común. Usa una más segura")
    if not re.search(r"[a-z]", password):
        raise ValueError("La contraseña debe contener al menos una letra minúscula")
    if not re.search(r"[A-Z]", password):
        raise ValueError("La contraseña debe contener al menos una letra mayúscula")
    if not re.search(r"\d", password):
        raise ValueError("La contraseña debe contener al menos un número")
    if not re.search(r"[!@#$%]", password):
        raise ValueError("La contraseña debe contener al menos un carácter especial (! @ # $ %)")
    return True

valid_prefixes = {"NO_DSNU", "DSU", "DPI", "NI", "DP"}

def validate_json_structure(json_data):
    for file, content in json_data.items():
        for key, value in content.items():
            if "CLASIFICADORES" in value:
                classifiers = value["CLASIFICADORES"]
                if "IS" in classifiers:
                    before_is = classifiers[:classifiers.index("IS")]
                    if len(before_is) == 0 or not any(prefix in before_is for prefix in valid_prefixes):
                        return False
                    if len(set(before_is)) != len(before_is) or before_is.count("IS") > 0:
                        return False
    return True

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_value(value, key):
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(value.encode()) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode(), iv, encryptor.tag

def encrypt_metadata(metadata, key, output_path):
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(json.dumps(metadata).encode()) + encryptor.finalize()
    
    encrypted_data = {
        "iv": base64.b64encode(iv).decode(),
        "tag": base64.b64encode(encryptor.tag).decode(),
        "data": base64.b64encode(ciphertext).decode()
    }
    
    with open(output_path, "w") as f:
        json.dump(encrypted_data, f)

def process_single_file(filename, input_dir, output_dir, key, salt):
    metadata = []
    filepath = os.path.join(input_dir, filename)
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            json_data = json.load(file)
        
        if not validate_json_structure(json_data):
            raise ValueError("ESTRUCTURA INCORRECTA Y CIFRADO INCORRECTO")
        
        encryption_counter = 1
        for file_key, content in json_data.items():
            for key_entry, value in content.items():
                if "CLASIFICADORES" in value:
                    classifiers = value["CLASIFICADORES"]
                    if "IS" in classifiers:
                        keys_to_encrypt = [k for k in list(value.keys()) if k != "CLASIFICADORES"]
                        for k in keys_to_encrypt:
                            if isinstance(value[k], list) and len(value[k]) > 0:
                                encrypted_list = []
                                inicio_contador = encryption_counter
                                for item in value[k]:
                                    encrypted, iv, tag = encrypt_value(item, key)
                                    encrypted_list.append(encrypted)
                                    metadata.append({
                                        "archivo": filename,
                                        "clave": f"{k}*{encryption_counter}",
                                        "iv": base64.b64encode(iv).decode(),
                                        "tag": base64.b64encode(tag).decode()
                                    })
                                    encryption_counter += 1
                                value[f"{k}*{inicio_contador}"] = encrypted_list
                                del value[k]
                            elif isinstance(value[k], str):
                                encrypted, iv, tag = encrypt_value(value[k], key)
                                value[f"{k}*{encryption_counter}"] = encrypted
                                metadata.append({
                                    "archivo": filename,
                                    "clave": f"{k}*{encryption_counter}",
                                    "iv": base64.b64encode(iv).decode(),
                                    "tag": base64.b64encode(tag).decode()
                                })
                                encryption_counter += 1
                                del value[k]

        output_path = os.path.join(output_dir, filename)
        with open(output_path, "w", encoding="utf-8") as output_file:
            json.dump(json_data, output_file, indent=4, ensure_ascii=False)
        return filename, metadata
    except Exception as e:
        raise ValueError(f"Error procesando {filename}: {str(e)}")

def cifrar_partes_sensibles_json(file_paths, password, output_dir, metadata_dir, salt_file_path):
    # Validar la contraseña primero
    try:
        is_valid_password(password)
    except ValueError as e:
        raise ValueError(f"Contraseña inválida: {str(e)}")
    
    # Load salt from file
    with open(salt_file_path, "r") as f:
        salt_data = json.load(f)
        salt = base64.b64decode(salt_data["salt"])
    
    key = derive_key(password, salt)
    metadata = []
    
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(metadata_dir, exist_ok=True)
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for file_path in file_paths:
            filename = os.path.basename(file_path)
            futures.append(executor.submit(process_single_file, filename, 
                                          os.path.dirname(file_path), 
                                          output_dir, key, salt))
        
        for future in concurrent.futures.as_completed(futures):
            try:
                filename, file_metadata = future.result()
                metadata.extend(file_metadata)
            except Exception as e:
                raise ValueError(str(e))
    
    # Encrypt metadata file
    metadata_path = os.path.join(metadata_dir, "metadatos.json")
    encrypt_metadata(metadata, key, metadata_path)
    
    # Encrypt metadata file
    metadata_path = os.path.join(metadata_dir, "metadatos.json")
    encrypt_metadata(metadata, key, metadata_path)