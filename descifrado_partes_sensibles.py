import os
import json
import base64
import concurrent.futures
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def decrypt_value(encrypted_value, key, iv, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(base64.b64decode(encrypted_value)) + decryptor.finalize()

def decrypt_metadata(metadata_path, key):
    with open(metadata_path, "r") as f:
        encrypted_data = json.load(f)
    
    iv = base64.b64decode(encrypted_data["iv"])
    tag = base64.b64decode(encrypted_data["tag"])
    ciphertext = base64.b64decode(encrypted_data["data"])
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    
    return json.loads(decrypted.decode())

def decrypt_file(filename, encrypted_dir, output_dir, metadata, key):
    filepath = os.path.join(encrypted_dir, filename)
    with open(filepath, "r", encoding="utf-8") as file:
        json_data = json.load(file)
    
    file_metadata = [m for m in metadata if m["archivo"] == filename]
    if not file_metadata:
        raise ValueError(f"No se encontraron metadatos para {filename}")
    
    for file_key, content in json_data.items():
        for key_entry, value in content.items():
            keys_to_decrypt = [k for k in value.keys() if "*" in k]
            
            for k in keys_to_decrypt:
                original_key = k.split("*")[0]
                matching_metadata = next((m for m in file_metadata if m["clave"] == k), None)
                
                if matching_metadata:
                    iv = base64.b64decode(matching_metadata["iv"])
                    tag = base64.b64decode(matching_metadata["tag"])
                    
                    if isinstance(value[k], list):
                        decrypted_list = [decrypt_value(item, key, iv, tag).decode() for item in value[k]]
                        value[original_key] = decrypted_list
                    else:
                        value[original_key] = decrypt_value(value[k], key, iv, tag).decode()
                    
                    del value[k]
    
    output_path = os.path.join(output_dir, filename)
    with open(output_path, "w", encoding="utf-8") as output_file:
        json.dump(json_data, output_file, indent=4, ensure_ascii=False)

def validate_password(metadata_path, salt, password):
    try:
        key = derive_key(password, salt)
        # Try to decrypt metadata to validate password
        decrypt_metadata(metadata_path, key)
        return True
    except Exception:
        return False

def descifrar_partes_sensibles_json(password, encrypted_dir, output_dir, metadata_dir, salt_file_path):
    # Load salt from file
    with open(salt_file_path, "r") as f:
        salt_data = json.load(f)
        salt = base64.b64decode(salt_data["salt"])
    
    metadata_path = os.path.join(metadata_dir, "metadatos.json")
    
    # Validate password first
    if not validate_password(metadata_path, salt, password):
        raise ValueError("Contraseña incorrecta")
    
    key = derive_key(password, salt)
    metadata = decrypt_metadata(metadata_path, key)
    
    os.makedirs(output_dir, exist_ok=True)
    
    json_files = [f for f in os.listdir(encrypted_dir) if f.endswith(".json")]
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for filename in json_files:
            futures.append(executor.submit(decrypt_file, filename, 
                                         encrypted_dir, output_dir, 
                                         metadata, key))
        
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                raise ValueError(f"Error al descifrar: {str(e)}")