import os
import json
import base64
import secrets

def generar_salt():
    # Definir rutas
    CARPETA_SALT = r"C:\Users\52554\Documents\ESCOM\PROTOCOLO\TT2\APP2\uploads\SALT"
    ARCHIVO_SALT = os.path.join(CARPETA_SALT, "salt.json")
    
    # Crear la carpeta si no existe
    os.makedirs(CARPETA_SALT, exist_ok=True)
    
    # Generar o cargar SALT existente
    if os.path.exists(ARCHIVO_SALT):
        with open(ARCHIVO_SALT, "r") as f:
            salt_data = json.load(f)
        salt = base64.b64decode(salt_data["salt"])
    else:
        salt = secrets.token_bytes(32)
        salt_data = {"salt": base64.b64encode(salt).decode()}
        
        with open(ARCHIVO_SALT, "w") as f:
            json.dump(salt_data, f, indent=4)
    
    return salt

# Ejemplo de uso
if __name__ == "__main__":
    salt = generar_salt()
    print("SALT generado/cargado correctamente")