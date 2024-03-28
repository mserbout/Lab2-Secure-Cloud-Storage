from flask import Flask, render_template, request, send_from_directory, jsonify
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
from wtforms.validators import InputRequired
from werkzeug.utils import secure_filename

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding

import secrets
import os
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'static/files'


class KeyManagementService:
    def __init__(self):
        self.current_mk = self.generate_mk()
        self.current_kek = self.generate_kek(self.current_mk)
        self.old_mk = None  # Initialize old MK as None
        self.cmk = self.generate_cmk()  # Generate Customer Master Key (CMK)

    def generate_mk(self):
        # Generate a Master Key (MK)
        mk = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        return mk

    def generate_kek(self, mk):
        # Generate a Key Encryption Key (KEK) using the Master Key
        kek = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            iterations=100000,
            backend=default_backend()
        ).derive(mk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        return kek

    def generate_cmk(self):
        # Generate Customer Master Key (CMK)
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def rotate_keys(self):
        # Rotate keys by setting the current MK and KEK as old, and generating new ones
        self.secure_delete_key(self.old_mk)
        self.old_mk = self.current_mk
        self.current_mk = self.generate_mk()
        self.current_kek = self.generate_kek(self.current_mk)

        self.cmk = self.generate_cmk()

    def reencrypt_file(self, file_path, old_kek):
        # Re-encrypt the file from the old KEK to the current KEK
        encrypted_chunks = decrypt_file(file_path + '.metadata', old_kek)

        # Encrypt the chunks with the current KEK
        reencrypted_chunks = []
        for chunk_data in encrypted_chunks:
            dek = bytes.fromhex(chunk_data['dek'])
            encrypted_data = chunk_data['ciphertext']
            cipher = AESGCM(dek)
            decrypted_data = cipher.decrypt(bytes.fromhex(chunk_data['nonce']), bytes.fromhex(encrypted_data), None)

            # Encrypt the decrypted data with the current KEK
            new_dek = generate_dek()
            new_encrypted_data = encrypt_data(decrypted_data, new_dek, self.current_kek)

            reencrypted_chunks.append({
                'dek': new_dek.hex(),
                'nonce': chunk_data['nonce'],
                'ciphertext': new_encrypted_data.hex()
            })

        # Update file metadata with re-encrypted chunks
        file_metadata = {
            'filename': file_path,
            'dek': new_dek.hex(),
            'chunks': reencrypted_chunks,
            'encryption_algorithm': 'AES-GCM',
            'key_id': self.current_kek.hex()  # Identifier for the KEK used
        }
        with open(file_path + '.metadata', 'w') as metadata_file:
            json.dump(file_metadata, metadata_file)

        return True

    def secure_delete_key(self, key):
        """
        Securely deletes a key by overwriting it with zeros/random data.
        """
        key_size = len(key)

        # Overwrite the key with zeros/random data
        if secrets.choice([True, False]):  # Randomly choose between zeroing out or using random data
            # Use random data
            new_key = secrets.token_bytes(key_size)
        else:
            # Zero out the key
            new_key = b'\x00' * key_size

        # Wipe out the original key by replacing its contents
        key[:key_size] = new_key

    def encrypt_kek_with_cmk(self, cmk, kek):
        # Encrypt KEK with CMK
        cipher_text = cmk.public_key().encrypt(
            kek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return cipher_text

    def retrieve_cmk(self, cmk_path):
        # Retrieve Customer Master Key (CMK)
        with open(cmk_path, 'rb') as f:
            cmk_bytes = f.read()
            cmk = serialization.load_pem_private_key(
                cmk_bytes,
                password=None,
                backend=default_backend()
            )
        return cmk



kms = KeyManagementService()


def generate_dek():
    return os.urandom(32)  #Generate Data Encryption Key (DEK) - DEK length is 32 bytes for AES-256


def encrypt_data(data, dek, kek):
    cipher = AESGCM(dek)
    nonce = os.urandom(12) 
    ciphertext = cipher.encrypt(nonce, data, None)
    return {
        'nonce': nonce.hex(),
        'ciphertext': ciphertext.hex()
    }


def decrypt_data(data, dek, kek):
    cipher = AESGCM(dek)
    nonce = bytes.fromhex(data['nonce'])
    ciphertext = bytes.fromhex(data['ciphertext'])
    decrypted_data = cipher.decrypt(nonce, ciphertext, None)
    return decrypted_data


def encrypt_file(file_path, dek, kek):
    encrypted_chunks = []  # List to store encrypted chunks

    # Encrypt file chunks with the DEK
    with open(file_path, 'rb') as f:
        chunk_size = 1024 * 1024  #1MB chunks
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            encrypted_chunk = encrypt_data(chunk, dek, kek)
            encrypted_chunks.append(encrypted_chunk)

    #Return the list of encrypted chunks
    return encrypted_chunks


def decrypt_file(file_metadata_path, kek):
    with open(file_metadata_path, 'r') as metadata_file:
        file_metadata = json.load(metadata_file)
        expected_encryption_algorithm = 'AES-GCM'  
        expected_key_id = kms.current_kek.hex()  

        # Check if file metadata matches expected values
        if (file_metadata.get('encryption_algorithm') != expected_encryption_algorithm or
                file_metadata.get('key_id') != expected_key_id):
            raise ValueError("File metadata has been tampered with.")

        dek = bytes.fromhex(file_metadata['dek'])
        encrypted_chunks = file_metadata['chunks']

        # Decrypt the file
        decrypted_chunks = []
        for chunk_data in encrypted_chunks:
            decrypted_data = decrypt_data(chunk_data, dek, kek)
            decrypted_chunks.append(decrypted_data)

        return decrypted_chunks


class UploadFileForm(FlaskForm):
    file = FileField("File", validators=[InputRequired()])
    submit = SubmitField("Upload File")


@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
def home():
    form = UploadFileForm()
    files = []

    if form.validate_on_submit():
        file = form.file.data
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Generate a unique DEK for this file
        dek = generate_dek()

        # Encrypt the file with the DEK and KEK
        encrypted_chunks = encrypt_file(file_path, dek, kms.current_kek)

        # Store DEK and encrypted chunks metadata
        file_metadata = {
            'filename': filename,
            'dek': dek.hex(),
            'chunks': encrypted_chunks,
            'encryption_algorithm': 'AES-GCM',
            'key_id': kms.current_kek.hex() 
        }
        with open(file_path + '.metadata', 'w') as metadata_file:
            json.dump(file_metadata, metadata_file)

        #Remove original file
        os.remove(file_path)

    # Fetch the list of files stored on the server
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        if filename.endswith('.metadata'):
            files.append(filename[:-9])  # Remove the '.metadata' extension

    return render_template('index.html', form=form, files=files)


@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    metadata_file_path = file_path + '.metadata'
    if os.path.exists(metadata_file_path):
        with open(metadata_file_path, 'r') as metadata_file:
            file_metadata = json.load(metadata_file)
            dek = bytes.fromhex(file_metadata['dek'])
            decrypted_chunks = decrypt_file(metadata_file_path, dek)
            decrypted_data = b''.join(decrypted_chunks)
        with open(file_path, 'wb') as f:
            f.write(decrypted_data)
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    else:
        return "File not found."


@app.route('/list_files', methods=['GET'])
def list_files():
    files = []
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        if filename.endswith('.metadata'):
            files.append(filename[:-9])
    return jsonify(files)


if __name__ == '__main__':
    app.run(debug=True)
