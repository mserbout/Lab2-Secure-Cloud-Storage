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
from flask import Flask, redirect, render_template, request, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash


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


app.config['SHARED_FOLDER'] = 'static/Shared folder'

def get_shared_folder():
    shared_folder = app.config['SHARED_FOLDER']
    if not os.path.exists(shared_folder):
        os.makedirs(shared_folder)
    return shared_folder

def get_user_file_folder(username):
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    return user_folder


from flask import flash

@app.route('/', methods=['GET', 'POST'])
def home():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    form = UploadFileForm()
    message = None  # Initialize message variable
    if form.validate_on_submit():
        file = form.file.data
        filename = secure_filename(file.filename)
        if 'share_file' in request.form:
            destination_folder = get_shared_folder()
        else:
            destination_folder = get_user_file_folder(session['username'])
        file_path = os.path.join(destination_folder, filename)
        file.save(file_path)
        encryption_algorithm = form.encryption_algorithm.data
        kms.encrypt_file(file_path, encryption_algorithm)

        message = "File has been uploaded and encrypted."  # Set success message
        flash(message, 'success')  # Flash the success message

        return redirect(url_for('home'))

    shared_files_folder = get_shared_folder()
    shared_files = [file for file in os.listdir(shared_files_folder) if not file.endswith('.encrypted')]
    return render_template('index.html', form=form,  shared_files=shared_files, username=session['username'], message=message)






@app.route('/download/<filename>')
def download(filename):
    user_folder = get_user_file_folder(session['username'])
    shared_folder = get_shared_folder()

    # Check if the file exists in the user's folder
    user_file_path = os.path.join(user_folder, filename)
    if os.path.exists(user_file_path):
        kms.decrypt_file(user_file_path)
        return send_from_directory(user_folder, filename, as_attachment=True)

    # Check if the file exists in the shared folder
    shared_file_path = os.path.join(shared_folder, filename)
    if os.path.exists(shared_file_path):
        # No need to decrypt shared files
        return send_from_directory(shared_folder, filename, as_attachment=True)

    # If the file is not found in either location, return an error message
    return "File not found."



@app.route('/list')
def list_files():
    user_files_folder = get_user_file_folder(session['username'])
    shared_folder = get_shared_folder()

    # Fetch files from the user's folder
    user_files = [file for file in os.listdir(user_files_folder) if not file.endswith('.encrypted')]
    
    # Fetch files from the shared folder
    shared_files = [file for file in os.listdir(shared_folder) if not file.endswith('.encrypted')]

    # Combine user files and shared files, ensuring uniqueness
    all_files = set(user_files + shared_files)

    return json.dumps(list(all_files))




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


@app.route('/dashboard')
def dashboard():
    if 'logged_in' in session:
        return render_template('dashboard.html')
    return redirect(url_for('login'))


# Load user data from JSON file
def load_users():
    try:
        with open('users.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

# Save user data to JSON file
def save_users(users):
    with open('users.json', 'w') as f:
        json.dump(users, f)

# User database
users = load_users()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            return "User already exists! Please choose a different username."
        users[username] = generate_password_hash(password)
        with open('users.json', 'r+') as f:
            data = json.load(f)
            data[username] = users[username]
            f.seek(0)
            json.dump(data, f)
            f.truncate()
        return redirect(url_for('login'))
    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if the username exists
        if username in users:
            # Check if the password matches
            if check_password_hash(users[username], password):
                # Set session variables for logged-in user
                session['logged_in'] = True
                session['username'] = username
                return redirect(url_for('home'))
        
        # If username or password is incorrect, show error message
        return render_template('login.html', error="Invalid username or password. Please try again.")

    # If it's a GET request, render the login form
    return render_template('login.html', error=None)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if request.method == 'POST':
        # Perform logout functionality
        session.pop('logged_in', None)
        session.pop('username', None)
        return redirect(url_for('login'))
    # If it's a GET request, just redirect to the login page
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)