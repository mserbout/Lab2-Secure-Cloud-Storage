from flask import Flask, render_template, request, send_from_directory
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import os
import json
from wtforms.validators import InputRequired

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'static/files'
app.config['CMK'] = Fernet.generate_key()  # Customer Master Key
app.config['DOWNLOAD_FOLDER'] = 'static/download'


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

    def encrypt_file(self, file_path):
        """
        Encrypts a file using the Data Encryption Key (DEK) and encrypts the DEK using the KEK.
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

                # Generate CMK and encrypt KEK
                cmk = self.request_key()
                cmk_cipher_suite = Fernet(cmk)
                encrypted_kek = cmk_cipher_suite.encrypt(kek)

                metadata = {
                    'filename': filename,
                    'chunk_index': chunk_index,
                    'encrypted_dek': encrypted_dek.decode()  # Convert bytes to string for serialization
                }

                # Encrypt the chunk with the DEK
                encrypted_chunk = fernet.encrypt(chunk)

                # Create a dictionary containing the encrypted chunk data and metadata
                encrypted_data_with_metadata = {
                    'data': encrypted_chunk.decode(),  # Convert bytes to string for serialization
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

        return encrypted_chunks_folder


    def decrypt_file(self, file_path):
        """
        Decrypts a file using the Data Encryption Key (DEK) retrieved using the filename and decrypts the DEK using the KEK.
        """
        filename = os.path.basename(file_path)

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

            # Create Fernet object with decrypted DEK
            fernet = Fernet(dek)

            # Read the rest of the file (encrypted data)
            encrypted_data = file.read()

            # Decrypt the data
            decrypted_data = fernet.decrypt(encrypted_data)

            # Write decrypted data to a new file
            decrypted_file_path = file_path.replace('.encrypted', '')
            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)

        return decrypted_file_path

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


kms = KMS()

class UploadFileForm(FlaskForm):
    file = FileField("File", validators=[InputRequired()])
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
        kms.encrypt_file(file_path)
        
        return "File has been uploaded and encrypted."
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



if __name__ == '__main__':
    app.run(debug=True)
