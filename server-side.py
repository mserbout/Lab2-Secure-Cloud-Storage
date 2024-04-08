import shutil
from flask import Flask, redirect, render_template, request, send_from_directory, url_for
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from wtforms.validators import InputRequired
from wtforms import FileField, SubmitField
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from flask_wtf import FlaskForm
from wtforms import SelectField
from fileinput import filename
import base64
import secrets
import hashlib
import json
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'static/files'
app.config['CMK'] = Fernet.generate_key()  # Customer Master Key
app.config['DOWNLOAD_FOLDER'] = 'static/download'
app.config['SHARED_FOLDER'] = 'static/Shared folder'

class KMS:
    def __init__(self):
        # self.deks = {}  # Data Encryption Keys (DEKs)
        # self.kek = Fernet.generate_key()  # Key Encryption Key (KEK)
        # self.mk = Fernet.generate_key()   # Master Key (MK)
        self.storage = {}

    def request_key(self):
        """
        Generates a Data Encryption Key (DEK).
        """
        return Fernet.generate_key()

    def encrypt_file(self, file_path, encryption_algorithm):
        if encryption_algorithm == 'fernet':
            return self.encrypt_file_with_fernet(file_path)
        elif encryption_algorithm == 'aes-gcm':
            return self.encrypt_file_with_aes_gcm(file_path)
        else:
            raise ValueError("Invalid encryption algorithm")

    def encrypt_file_with_fernet(self, file_path):
        """
        Encrypts a file using the Fernet algorithm.
        """
        CHUNK_SIZE = 1024 * 1024  # 1MB chunk size (adjust as needed)
        filename = os.path.basename(file_path)
        encrypted_chunks_folder = 'static/encrypted_chunks'  # Folder to store encrypted chunks
        if not os.path.exists(encrypted_chunks_folder):
            os.makedirs(encrypted_chunks_folder)

        with open(file_path, 'rb') as file:
            chunk_index = 0
            while True:
                chunk = file.read(CHUNK_SIZE)
                if not chunk:
                    break

                # Generate a unique DEK for each chunk
                dek = self.request_key()
                fernet = Fernet(dek)

                # Generate KEK and encrypt DEK
                kek = self.request_key()
                kek_cipher_suite = Fernet(kek)
                encrypted_dek = kek_cipher_suite.encrypt(dek)
                # Store encrypted dEK for later decryption
                self.storage[filename] = {'encrypted_kek': encrypted_dek}

                # Generate CMK and encrypt KEK
                cmk = self.request_key()
                cmk_cipher_suite = Fernet(cmk)
                encrypted_kek = cmk_cipher_suite.encrypt(kek)

                # Store encrypted KEK for later decryption
                self.storage[filename] = {'encrypted_kek': encrypted_kek}

                # Create metadata
                metadata = {
                    'filename': filename,
                    'chunk_index': chunk_index,
                    'algorithm': 'Fernet',
                    'key_id': hashlib.sha256(dek).hexdigest()
                }

                 # Encrypt the chunk with the DEK
                encrypted_chunk = fernet.encrypt(chunk)

                # Calculate authentication tag based on encrypted data and metadata
                authentication_tag = hashlib.sha256(encrypted_chunk + json.dumps(metadata).encode()).hexdigest()

                # Create a dictionary containing the encrypted chunk data and metadata
                encrypted_data_with_metadata = {
                     'data': base64.b64encode(encrypted_chunk).decode(),  # Encode bytes to Base64
                     'metadata': metadata,
                     'authentication_tag': authentication_tag
                }

                # Serialize data with metadata to JSON and encode as bytes
                encrypted_data_json = json.dumps(encrypted_data_with_metadata)
                encrypted_data_bytes = encrypted_data_json.encode()

                # Write the encrypted data to a separate file
                encrypted_chunk_filename = f'{filename}_chunk_{chunk_index}.encrypted'
                encrypted_chunk_path = os.path.join(encrypted_chunks_folder, encrypted_chunk_filename)
                with open(encrypted_chunk_path, 'wb') as encrypted_chunk_file:
                    encrypted_chunk_file.write(encrypted_data_bytes)

                chunk_index += 1
        return encrypted_chunks_folder

    def encrypt_file_with_aes_gcm(self, file_path):
        """
        Encrypts a file using the AES-GCM algorithm.
        """
        CHUNK_SIZE = 1024 * 1024  
        filename = os.path.basename(file_path)
        encrypted_chunks_folder = 'static/encrypted_chunks'  # Folder to store encrypted chunks
        if not os.path.exists(encrypted_chunks_folder):
            os.makedirs(encrypted_chunks_folder)

        with open(file_path, 'rb') as file:
            chunk_index = 0
            while True:
                chunk = file.read(CHUNK_SIZE)
                if not chunk:
                    break

                # Generate a unique DEK for each chunk
                dek = secrets.token_bytes(64)  

                # Generate a unique nonce
                nonce = secrets.token_bytes(12)  

                # Create AES-GCM cipher
                cipher = Cipher(algorithms.AES(dek[:32]), modes.GCM(nonce), backend=default_backend())
                encryptor = cipher.encryptor()

                # Encrypt the chunk
                encrypted_chunk = encryptor.update(chunk) + encryptor.finalize()

                # Get the authentication tag
                authentication_tag = encryptor.tag

                # Create metadata
                metadata = {
                    'filename': filename,
                    'chunk_index': chunk_index,
                    'algorithm': 'AES-GCM',
                    'key_id': hashlib.sha256(dek).hexdigest(),
                    'nonce': base64.b64encode(nonce).decode(),
                    'authentication_tag': base64.b64encode(authentication_tag).decode()
                }

                # Create a dictionary containing the encrypted chunk data and metadata
                encrypted_data_with_metadata = {
                    'data': base64.b64encode(encrypted_chunk).decode(),  # Encode bytes to Base64
                    'metadata': metadata
                }

                # Serialize data with metadata to JSON and encode as bytes
                encrypted_data_json = json.dumps(encrypted_data_with_metadata)
                encrypted_data_bytes = encrypted_data_json.encode()

                # Write the encrypted data to a separate file
                encrypted_chunk_filename = f'{filename}_chunk_{chunk_index}.encrypted'
                encrypted_chunk_path = os.path.join(encrypted_chunks_folder, encrypted_chunk_filename)
                with open(encrypted_chunk_path, 'wb') as encrypted_chunk_file:
                    encrypted_chunk_file.write(encrypted_data_bytes)

                chunk_index += 1

                # Store DEK for later decryption
                self.storage[filename] = {'dek': dek}

        return encrypted_chunks_folder


    def decrypt_file(self, file_path):
        """
        Decrypts a file using the appropriate encryption algorithm determined from metadata.
        """
        with open(file_path, 'rb') as file:
            # Read metadata length
            metadata_length = len(self.request_key())
            metadata_bytes = file.read(metadata_length)

            # Check if bytes can be decoded to UTF-8
            try:
                metadata = json.loads(metadata_bytes.decode('utf-8'))
            except UnicodeDecodeError:
                print("Unable to decode metadata. The file may not be a valid encrypted file.")
                return
            
            # Verify metadata integrity
            if not self.verify_metadata_integrity(metadata):
                print("Metadata integrity verification failed. File may have been tampered with.")
                return

            # Determine encryption algorithm from metadata
            algorithm = metadata.get('algorithm')
            if algorithm == 'Fernet':
                self.decrypt_file_with_fernet(file, metadata)
            elif algorithm == 'AES-GCM':
                self.decrypt_file_with_aes_gcm(file, metadata)
            else:
                print("Unsupported encryption algorithm.")
                return

    def decrypt_file_with_fernet(self, file, metadata, file_path):
        """
        Decrypts a file encrypted using the Fernet algorithm.
        """
       # Get encrypted DEK from metadata
        encrypted_dek = metadata.get('encrypted_dek')

        # Retrieve CMK and encrypted KEK from storage based on filename
        storage_data = self.storage.get(filename)
        if not storage_data:
            print("No stored keys found for the file.")
            return
        encrypted_kek = storage_data.get('encrypted_kek')
        cmk = storage_data.get('cmk')

        # Decrypt KEK using CMK
        cmk_cipher_suite = Fernet(cmk)
        kek = cmk_cipher_suite.decrypt(encrypted_kek.encode())

        # Decrypt DEK using KEK
        kek_cipher_suite = Fernet(kek)
        dek = kek_cipher_suite.decrypt(encrypted_dek.encode())

        # Create Fernet object with DEK
        fernet = Fernet(dek)

        # Decrypt each chunk
        decrypted_data = b""
        for chunk_index in range(metadata['chunk_index'] + 1):
            encrypted_data = self.read_next_encrypted_chunk(file, chunk_index)
            decrypted_chunk = fernet.decrypt(encrypted_data)
            decrypted_data += decrypted_chunk

        # Calculate authentication tag from decrypted data and metadata
        calculated_tag = hash.Hash(hash.SHA256(), backend=default_backend())
        calculated_tag.update(decrypted_data)
        calculated_tag.update(json.dumps(metadata).encode())
        authentication_tag = calculated_tag.finalize()

        # Compare authentication tag with original tag
        original_tag = base64.b64decode(metadata['authentication_tag'].encode())
        if authentication_tag != original_tag:
            print("Authentication tag verification failed. Data may have been tampered with.")
            return    

        # Write decrypted data to a new file
        decrypted_file_path = file_path.replace('.encrypted', '')
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

    def decrypt_file_with_aes_gcm(self, file, metadata, file_path):
        """
        Decrypts a file encrypted using the AES-GCM algorithm.
        """
        # Get DEK from metadata
        dek = self.get_dek_from_metadata(metadata)

        # Derive encryption key and nonce from DEK
        encryption_key = dek[:32]  
        nonce = dek[32:]  

        # Create AES-GCM cipher
        cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt each chunk
        decrypted_data = b""
        for chunk_index in range(metadata['chunk_index'] + 1):
            encrypted_data = self.read_next_encrypted_chunk(file, chunk_index)
            decrypted_chunk = decryptor.update(encrypted_data) + decryptor.finalize()
            decrypted_data += decrypted_chunk

        # Calculate authentication tag from decrypted data and metadata
        calculated_tag = decryptor.tag
        original_tag = base64.b64decode(metadata['authentication_tag'].encode())

        # Compare authentication tag with original tag
        if calculated_tag != original_tag:
            print("Authentication tag verification failed. Data may have been tampered with.")
            return    

        # Write decrypted data to a new file
        decrypted_file_path = file_path.replace('.encrypted', '')
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)
    
    def verify_metadata_integrity(self, metadata):
        """
        Verify integrity of file metadata.
        """
        # Calculate hash of metadata without 'hash' field
        metadata_without_hash = metadata.copy()
        metadata_without_hash.pop('hash', None)
        metadata_hash = hashlib.sha256(json.dumps(metadata_without_hash).encode()).hexdigest()

        # Compare calculated hash with provided hash in metadata
        if 'hash' in metadata and metadata['hash'] == metadata_hash:
            return True
        else:
            return False
    
    def rotate_master_key(self):
        """
        Rotate the Master Key (MK) by generating a new one.
        """
        old_mk = app.config['CMK']
        new_mk = Fernet.generate_key()  
        app.config['CMK'] = new_mk
        self.reencrypt_deks(old_mk, new_mk)  

    def reencrypt_deks(self, old_mk, new_mk):
        """
        Re-encrypts all Data Encryption Keys (DEKs) using the new Master Key (MK).
        """
        for filename, data in self.storage.items():
            encrypted_dek = data.get('encrypted_dek')
            if encrypted_dek:
                dek = Fernet(old_mk).decrypt(encrypted_dek.encode())
                new_encrypted_dek = Fernet(new_mk).encrypt(dek)
                data['encrypted_dek'] = new_encrypted_dek.decode()


    def delete_dek(self, filename):
        """
        Securely deletes a Data Encryption Key (DEK) associated with a file.
        """
        dek = self.deks.pop(filename, None)
        if dek:
            # Overwrite the DEK with zeros
            dek_length = len(dek)
            overwritten_dek = bytes([0] * dek_length)
            self.deks[filename] = overwritten_dek
            return True
        else:
            return False


    def grant_access(self, filename, user):
        """
        Grant access to a user for a specific file.
        """
        shared_folder_path = app.config['SHARED_FOLDER']
        user_shared_folder = os.path.join(shared_folder_path, user)
        if not os.path.exists(user_shared_folder):
            os.makedirs(user_shared_folder)
        src_file = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        dest_file = os.path.join(user_shared_folder, filename)
        if os.path.exists(src_file):
            shutil.copy(src_file, dest_file)
            return True
        else:
            return False

    def revoke_access(self, filename, user):
        """
        Revoke access to a file from a user.
        """
        user_shared_folder = os.path.join(app.config['SHARED_FOLDER'], user)
        file_path = os.path.join(user_shared_folder, filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            return True
        else:
            return False

kms = KMS()

class UploadFileForm(FlaskForm):
    file = FileField("File", validators=[InputRequired()])
    encryption_algorithm = SelectField("Encryption Algorithm", choices=[('fernet', 'Fernet'), ('aes-gcm', 'AES-GCM')])
    submit = SubmitField("Upload File")




@app.route('/', methods=['GET', 'POST'])
def home():
    form = UploadFileForm()
    original_files = [file for file in os.listdir(app.config['UPLOAD_FOLDER']) if not file.endswith('.encrypted')]
    if form.validate_on_submit():
        file = form.file.data
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        encryption_algorithm = form.encryption_algorithm.data
        kms.encrypt_file(file_path, encryption_algorithm)

        return "File has been uploaded and encrypted. If you need to download file, updat windows"
    return render_template('index.html', form=form, files=original_files)



@app.route('/download/<filename>')
def download(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    kms.decrypt_file(file_path)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/list')
def list_files():
    #original_files = [file for file in os.listdir(app.config['UPLOAD_FOLDER']) if not file.endswith('.encrypted')]
    original_files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('list.html', files=original_files)

@app.route('/share/<filename>', methods=['POST'])
def share(filename):
    if request.method == 'POST':
        user = request.form['user']
        if kms.grant_access(filename, user):
            return redirect(url_for('list_files'))
        else:
            return "File does not exist or cannot be shared."
    return redirect(url_for('list_files'))

@app.route('/unshare/<filename>', methods=['POST'])
def unshare(filename):
    if request.method == 'POST':
        user = request.form['user']
        if kms.revoke_access(filename, user):
            return redirect(url_for('list_files'))
        else:
            return "File does not exist or cannot be unshared."
    return redirect(url_for('list_files'))

if __name__ == '__main__':
    app.run(debug=True)