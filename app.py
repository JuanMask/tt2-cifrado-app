from flask import Flask, render_template, request, redirect, url_for, send_file, flash
import os
import shutil
import threading
import time
from werkzeug.utils import secure_filename
from cifrado import cifrar_archivos
from descifrado import descifrar_archivos
from cifrado_partes_sensibles import cifrar_partes_sensibles_json
from descifrado_partes_sensibles import descifrar_partes_sensibles_json
import zipfile
from flask import jsonify


app = Flask(__name__)
app.secret_key = 'tu_clave_secreta_aqui'

# Configuración de directorios
UPLOAD_FOLDER = r"C:\Users\52554\Documents\ESCOM\PROTOCOLO\TT2\APP2\uploads"
ENCRYPTED_FOLDER = os.path.join(UPLOAD_FOLDER, "DOCUMENTOS_CIFRADOS")
DECRYPTED_FOLDER = os.path.join(UPLOAD_FOLDER, "DOCUMENTOS_DESCIFRADOS")
JSON_ENCRYPTED_FOLDER = os.path.join(UPLOAD_FOLDER, "JSON_CIFRADOS")
JSON_DECRYPTED_FOLDER = os.path.join(UPLOAD_FOLDER, "JSON_DESCIFRADOS")
JSON_SENSIBLE_ENCRYPTED_FOLDER = os.path.join(UPLOAD_FOLDER, "JSON_SENSIBLE_CIFRADOS")
JSON_SENSIBLE_DECRYPTED_FOLDER = os.path.join(UPLOAD_FOLDER, "JSON_SENSIBLE_DESCIFRADOS")
METADATA_FOLDER = os.path.join(UPLOAD_FOLDER, "METADATOS")
SALT_FOLDER = os.path.join(UPLOAD_FOLDER, "SALT")

# Asegurar que las carpetas existan
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)
os.makedirs(JSON_ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(JSON_DECRYPTED_FOLDER, exist_ok=True)
os.makedirs(JSON_SENSIBLE_ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(JSON_SENSIBLE_DECRYPTED_FOLDER, exist_ok=True)
os.makedirs(METADATA_FOLDER, exist_ok=True)
os.makedirs(SALT_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ENCRYPTED_FOLDER'] = ENCRYPTED_FOLDER
app.config['DECRYPTED_FOLDER'] = DECRYPTED_FOLDER
app.config['JSON_ENCRYPTED_FOLDER'] = JSON_ENCRYPTED_FOLDER
app.config['JSON_DECRYPTED_FOLDER'] = JSON_DECRYPTED_FOLDER
app.config['JSON_SENSIBLE_ENCRYPTED_FOLDER'] = JSON_SENSIBLE_ENCRYPTED_FOLDER
app.config['JSON_SENSIBLE_DECRYPTED_FOLDER'] = JSON_SENSIBLE_DECRYPTED_FOLDER
app.config['METADATA_FOLDER'] = METADATA_FOLDER
app.config['SALT_FOLDER'] = SALT_FOLDER

def limpiar_carpeta(carpeta):
    """Función mejorada para limpiar una carpeta de forma segura"""
    try:
        for f in os.listdir(carpeta):
            file_path = os.path.join(carpeta, f)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                app.logger.error(f"Error al eliminar {file_path}: {e}")
                time.sleep(1)
                try:
                    if os.path.exists(file_path):
                        if os.path.isfile(file_path):
                            os.unlink(file_path)
                        else:
                            shutil.rmtree(file_path)
                except Exception as e2:
                    app.logger.error(f"Error persistente con {file_path}: {e2}")
    except Exception as e:
        app.logger.error(f"Error al listar carpeta {carpeta}: {e}")

def handle_regular_encryption(request, password):
    if 'files' not in request.files:
        flash('No se seleccionaron archivos', 'error')
        return redirect(url_for('index'))
        
    files = request.files.getlist('files')
    if len(files) == 0:
        flash('No se seleccionaron archivos', 'error')
        return redirect(url_for('index'))
    
    file_paths = []
    for file in files:
        if file.filename == '':
            continue
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        file_paths.append(file_path)
    
    limpiar_carpeta(app.config['ENCRYPTED_FOLDER'])
    
    try:
        salt_file_path = os.path.join(app.config['SALT_FOLDER'], 'salt.json')
        cifrar_archivos(file_paths, password, app.config['ENCRYPTED_FOLDER'], salt_file_path)
        flash('ARCHIVOS CIFRADOS CORRECTAMENTE', 'success')
    except Exception as e:
        flash(str(e), 'error')
    
    for file_path in file_paths:
        if os.path.exists(file_path):
            os.remove(file_path)
    
    return redirect(url_for('index'))

def handle_json_encryption(request, password):
    if 'files' not in request.files:
        flash('No se seleccionaron archivos', 'error')
        return redirect(url_for('index'))
        
    files = request.files.getlist('files')
    if len(files) == 0:
        flash('No se seleccionaron archivos', 'error')
        return redirect(url_for('index'))
    
    for file in files:
        if not file.filename.lower().endswith('.json'):
            flash('Solo se permiten archivos JSON para esta opción', 'error')
            return redirect(url_for('index'))
    
    file_paths = []
    for file in files:
        if file.filename == '':
            continue
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        file_paths.append(file_path)
    
    limpiar_carpeta(app.config['JSON_ENCRYPTED_FOLDER'])
    
    try:
        salt_file_path = os.path.join(app.config['SALT_FOLDER'], 'salt.json')
        cifrar_archivos(file_paths, password, app.config['JSON_ENCRYPTED_FOLDER'], salt_file_path)
        flash('ARCHIVOS JSON CIFRADOS CORRECTAMENTE', 'success')
    except Exception as e:
        flash(str(e), 'error')
    
    for file_path in file_paths:
        if os.path.exists(file_path):
            os.remove(file_path)
    
    return redirect(url_for('index'))

def handle_sensitive_json_encryption(request, password):
    if 'files' not in request.files:
        flash('No se seleccionaron archivos', 'error')
        return redirect(url_for('index'))
        
    files = request.files.getlist('files')
    if len(files) == 0:
        flash('No se seleccionaron archivos', 'error')
        return redirect(url_for('index'))
    
    for file in files:
        if not file.filename.lower().endswith('.json'):
            flash('Solo se permiten archivos JSON para esta opción', 'error')
            return redirect(url_for('index'))
    
    file_paths = []
    for file in files:
        if file.filename == '':
            continue
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        file_paths.append(file_path)
    
    limpiar_carpeta(app.config['JSON_SENSIBLE_ENCRYPTED_FOLDER'])
    limpiar_carpeta(app.config['METADATA_FOLDER'])
    
    try:
        salt_file_path = os.path.join(app.config['SALT_FOLDER'], 'salt.json')
        cifrar_partes_sensibles_json(file_paths, password, 
                                   app.config['JSON_SENSIBLE_ENCRYPTED_FOLDER'],
                                   app.config['METADATA_FOLDER'],
                                   salt_file_path)
        flash('PARTES SENSIBLES DEL ARCHIVO JSON CIFRADAS CORRECTAMENTE', 'success')
    except ValueError as e:
        flash(f'Error: {str(e)}', 'error')
    except Exception as e:
        flash(f'Error durante el cifrado: {str(e)}', 'error')
    
    for file_path in file_paths:
        if os.path.exists(file_path):
            os.remove(file_path)
    
    return redirect(url_for('index'))
# Add this new handler function
def handle_sensitive_json_decryption(password):
    try:
        limpiar_carpeta(app.config['JSON_SENSIBLE_DECRYPTED_FOLDER'])
        
        salt_file_path = os.path.join(app.config['SALT_FOLDER'], 'salt.json')
        descifrar_partes_sensibles_json(password, 
                                      app.config['JSON_SENSIBLE_ENCRYPTED_FOLDER'],
                                      app.config['JSON_SENSIBLE_DECRYPTED_FOLDER'],
                                      app.config['METADATA_FOLDER'],
                                      salt_file_path)
        
        decrypted_files = [f for f in os.listdir(app.config['JSON_SENSIBLE_DECRYPTED_FOLDER']) 
                         if not f.endswith('.zip')]
        if not decrypted_files:
            flash('No se encontraron archivos descifrados', 'error')
            return redirect(url_for('index'))
        
        zip_path = os.path.join(app.config['JSON_SENSIBLE_DECRYPTED_FOLDER'], 'json_sensible_descifrados.zip')
        if os.path.exists(zip_path):
            os.remove(zip_path)
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in decrypted_files:
                file_path = os.path.join(app.config['JSON_SENSIBLE_DECRYPTED_FOLDER'], file)
                zipf.write(file_path, os.path.basename(file_path))
        
        return redirect(url_for('sensible_json_download_page'))
        
    except Exception as e:
        flash(f'Error durante el descifrado: {str(e)}', 'error')
        return redirect(url_for('index'))

def handle_regular_decryption(password):
    try:
        limpiar_carpeta(app.config['DECRYPTED_FOLDER'])
        
        salt_file_path = os.path.join(app.config['SALT_FOLDER'], 'salt.json')
        descifrar_archivos(password, app.config['ENCRYPTED_FOLDER'], 
                         app.config['DECRYPTED_FOLDER'], salt_file_path)
        
        decrypted_files = [f for f in os.listdir(app.config['DECRYPTED_FOLDER']) 
                        if not f.endswith('.zip')]
        if not decrypted_files:
            flash('No se encontraron archivos descifrados', 'error')
            return redirect(url_for('index'))
        
        zip_path = os.path.join(app.config['DECRYPTED_FOLDER'], 'descifrados.zip')
        if os.path.exists(zip_path):
            os.remove(zip_path)
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in decrypted_files:
                file_path = os.path.join(app.config['DECRYPTED_FOLDER'], file)
                zipf.write(file_path, os.path.basename(file_path))
        
        return redirect(url_for('download_page'))
        
    except Exception as e:
        flash(f'Error durante el descifrado: {str(e)}', 'error')
        return redirect(url_for('index'))

def handle_json_decryption(password):
    try:
        limpiar_carpeta(app.config['JSON_DECRYPTED_FOLDER'])
        
        salt_file_path = os.path.join(app.config['SALT_FOLDER'], 'salt.json')
        descifrar_archivos(password, app.config['JSON_ENCRYPTED_FOLDER'], 
                         app.config['JSON_DECRYPTED_FOLDER'], salt_file_path)
        
        decrypted_files = [f for f in os.listdir(app.config['JSON_DECRYPTED_FOLDER']) 
                        if not f.endswith('.zip')]
        if not decrypted_files:
            flash('No se encontraron archivos JSON descifrados', 'error')
            return redirect(url_for('index'))
        
        zip_path = os.path.join(app.config['JSON_DECRYPTED_FOLDER'], 'json_descifrados.zip')
        if os.path.exists(zip_path):
            os.remove(zip_path)
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in decrypted_files:
                file_path = os.path.join(app.config['JSON_DECRYPTED_FOLDER'], file)
                zipf.write(file_path, os.path.basename(file_path))
        
        return redirect(url_for('json_download_page'))
        
    except Exception as e:
        flash(f'Error durante el descifrado: {str(e)}', 'error')
        return redirect(url_for('index'))


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        operation = request.form.get('operation')
        password = request.form.get('password')
        encrypt_type = request.form.get('encryptType')
        decrypt_type = request.form.get('decryptType')
        
        if not password:
            flash('Por favor ingrese una contraseña', 'error')
            return redirect(url_for('index'))
        
        if operation == 'encrypt':
            if encrypt_type == 'json_only':
                return handle_json_encryption(request, password)
            elif encrypt_type == 'partial':
                return handle_sensitive_json_encryption(request, password)
            else:
                return handle_regular_encryption(request, password)
                
        elif operation == 'decrypt':
            if decrypt_type == 'json_only':
                return handle_json_decryption(password)
            elif decrypt_type == 'partial':
                return handle_sensitive_json_decryption(password)
            else:
                return handle_regular_decryption(password)
    
    return render_template('index.html')

@app.route('/download-page')
def download_page():
    zip_path = os.path.join(app.config['DECRYPTED_FOLDER'], 'descifrados.zip')
    if not os.path.exists(zip_path):
        flash('No hay archivos listos para descargar', 'error')
        return redirect(url_for('index'))
    
    return render_template('download.html', is_json=False)

@app.route('/json-download-page')
def json_download_page():
    zip_path = os.path.join(app.config['JSON_DECRYPTED_FOLDER'], 'json_descifrados.zip')
    if not os.path.exists(zip_path):
        flash('No hay archivos JSON listos para descargar', 'error')
        return redirect(url_for('index'))
    
    return render_template('download.html', is_json=True)

@app.route('/json-sensible-download-page')
def json_sensible_download_page():
    zip_path = os.path.join(app.config['JSON_SENSIBLE_DECRYPTED_FOLDER'], 'json_sensible_descifrados.zip')
    if not os.path.exists(zip_path):
        flash('No hay archivos JSON listos para descargar', 'error')
        return redirect(url_for('index'))
    
    return render_template('download.html', is_json=True, is_sensible=True)

@app.route('/download-file')
def download_file():
    zip_path = os.path.join(app.config['DECRYPTED_FOLDER'], 'descifrados.zip')
    if os.path.exists(zip_path):
        def clean_decrypted_files():
            try:
                time.sleep(3)
                for filename in os.listdir(app.config['DECRYPTED_FOLDER']):
                    file_path = os.path.join(app.config['DECRYPTED_FOLDER'], filename)
                    if filename != 'descifrados.zip' and os.path.isfile(file_path):
                        os.unlink(file_path)
                        app.logger.info(f"Eliminado archivo descifrado: {filename}")
                
                time.sleep(5)
                if os.path.exists(zip_path):
                    os.unlink(zip_path)
                    app.logger.info("Archivo ZIP eliminado después de descarga")
            except Exception as e:
                app.logger.error(f"Error en limpieza: {str(e)}")

        threading.Thread(target=clean_decrypted_files, daemon=True).start()
        
        return send_file(
            zip_path,
            as_attachment=True,
            download_name='documentos_descifrados.zip'
        )
    else:
        flash('No hay archivos listos para descargar', 'error')
        return redirect(url_for('index'))

@app.route('/json-download-file')
def json_download_file():
    zip_path = os.path.join(app.config['JSON_DECRYPTED_FOLDER'], 'json_descifrados.zip')
    if os.path.exists(zip_path):
        def clean_json_files():
            try:
                time.sleep(3)
                for filename in os.listdir(app.config['JSON_DECRYPTED_FOLDER']):
                    file_path = os.path.join(app.config['JSON_DECRYPTED_FOLDER'], filename)
                    if filename != 'json_descifrados.zip' and os.path.isfile(file_path):
                        os.unlink(file_path)
                
                time.sleep(5)
                if os.path.exists(zip_path):
                    os.unlink(zip_path)
            except Exception as e:
                app.logger.error(f"Error limpiando JSON: {str(e)}")

        threading.Thread(target=clean_json_files, daemon=True).start()
        
        return send_file(
            zip_path,
            as_attachment=True,
            download_name='json_descifrados.zip'
        )
    else:
        flash('No hay archivos JSON para descargar', 'error')
        return redirect(url_for('index'))

@app.route('/sensible-json-download-page')
def sensible_json_download_page():
    zip_path = os.path.join(app.config['JSON_SENSIBLE_DECRYPTED_FOLDER'], 'json_sensible_descifrados.zip')
    if not os.path.exists(zip_path):
        flash('No hay archivos listos para descargar', 'error')
        return redirect(url_for('index'))
    
    return render_template('download.html', is_json=True)

@app.route('/sensible-json-download-file')
def sensible_json_download_file():
    zip_path = os.path.join(app.config['JSON_SENSIBLE_DECRYPTED_FOLDER'], 'json_sensible_descifrados.zip')
    if os.path.exists(zip_path):
        # Primero enviamos el archivo
        response = send_file(
            zip_path,
            as_attachment=True,
            download_name='json_sensible_descifrados.zip'
        )
        
        # Luego programamos la limpieza
        def clean_sensible_json_files():
            try:
                time.sleep(2)  # Esperar un poco para asegurar que la descarga comenzó
                
                # Eliminar archivos descifrados individuales
                for filename in os.listdir(app.config['JSON_SENSIBLE_DECRYPTED_FOLDER']):
                    file_path = os.path.join(app.config['JSON_SENSIBLE_DECRYPTED_FOLDER'], filename)
                    if filename != 'json_sensible_descifrados.zip' and os.path.isfile(file_path):
                        os.unlink(file_path)
                
                # Esperar un poco más antes de eliminar el ZIP
                time.sleep(5)
                if os.path.exists(zip_path):
                    os.unlink(zip_path)
            except Exception as e:
                app.logger.error(f"Error limpiando JSON sensible: {str(e)}")

        threading.Thread(target=clean_sensible_json_files, daemon=True).start()
        
        return response
    else:
        flash('No hay archivos JSON para descargar', 'error')
        return redirect(url_for('index'))

@app.route('/check-cleanup')
def check_cleanup():
    zip_path = os.path.join(app.config['DECRYPTED_FOLDER'], 'descifrados.zip')
    decrypted_files = [f for f in os.listdir(app.config['DECRYPTED_FOLDER']) 
                      if not f.endswith('.zip')]
    
    return jsonify({
        'cleaned': not os.path.exists(zip_path) and len(decrypted_files) == 0
    })

@app.route('/check-json-cleanup')
def check_json_cleanup():
    zip_path = os.path.join(app.config['JSON_DECRYPTED_FOLDER'], 'json_descifrados.zip')
    decrypted_files = [f for f in os.listdir(app.config['JSON_DECRYPTED_FOLDER']) 
                      if not f.endswith('.zip')]
    
    return jsonify({
        'cleaned': not os.path.exists(zip_path) and len(decrypted_files) == 0
    })

@app.route('/check-sensible-json-cleanup')
def check_sensible_json_cleanup():
    zip_path = os.path.join(app.config['JSON_SENSIBLE_DECRYPTED_FOLDER'], 'json_sensible_descifrados.zip')
    decrypted_files = [f for f in os.listdir(app.config['JSON_SENSIBLE_DECRYPTED_FOLDER']) 
                      if not f.endswith('.zip')]
    
    cleaned = not os.path.exists(zip_path) and len(decrypted_files) == 0
    
    # Si no está limpio pero el zip ya no existe, forzar limpieza
    if not cleaned and not os.path.exists(zip_path):
        limpiar_carpeta(app.config['JSON_SENSIBLE_DECRYPTED_FOLDER'])
        cleaned = True
    
    return jsonify({'cleaned': cleaned})

if __name__ == '__main__':
    app.run(debug=True)