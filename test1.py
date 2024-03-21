from cryptography.fernet import Fernet
import os

# Generate a key for encryption and decryption
MASTER_KEY = Fernet.generate_key()  

class Client:
    def __init__(self, server, kms):
        self.server = server
        self.kms = kms

    def upload(self, filename):
        with open(filename, 'rb') as f:
            data = f.read()
        
        dek = self.kms.request_key(filename)  # Request DEK from KMS
        cipher_suite = Fernet(dek)
        encrypted_data = cipher_suite.encrypt(data)
        self.server.store(filename, encrypted_data)

    def download(self, filename, output_filename):
        encrypted_data = self.server.retrieve(filename)
        if encrypted_data:
            dek = self.kms.request_key(filename)  # Request DEK from KMS
            cipher_suite = Fernet(dek)
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            with open(output_filename, 'wb') as f:
                f.write(decrypted_data)
            print("File downloaded successfully!")
        else:
            print("File not found!")

    def list_files(self):
        return self.server.list_files()

    def client_cli(self):
        while True:
            print("\nCommands:")
            print("1. Upload file")
            print("2. Download file")
            print("3. List files")
            print("4. Exit")
            choice = input("Enter your choice: ")

            if choice == '1':
                filename = input("Enter filename to upload: ")
                self.upload(filename)
                print("File uploaded successfully!")
            elif choice == '2':
                filename = input("Enter filename to download: ")
                output_filename = input("Enter output filename: ")
                self.download(filename, output_filename)
            elif choice == '3':
                files = self.list_files()
                print("Files in server:", files)
            elif choice == '4':
                break
            else:
                print("Invalid choice!")

class Server:
    def __init__(self, master_key):
        self.storage = {}
        self.master_key = master_key

    def store(self, filename, data):
        # Server-side encryption using Customer Master Key
        cipher_suite = Fernet(self.master_key)
        encrypted_data = cipher_suite.encrypt(data)
        self.storage[filename] = encrypted_data

    def retrieve(self, filename):
        # Server-side decryption using Customer Master Key
        if filename in self.storage:
            cipher_suite = Fernet(self.master_key)
            return cipher_suite.decrypt(self.storage[filename])
        else:
            return None

    def list_files(self):
        return list(self.storage.keys())

    def server_cli(self):
        while True:
            print("\nCommands:")
            print("1. List files")
            print("2. Exit")
            choice = input("Enter your choice: ")

            if choice == '1':
                files = self.list_files()
                print("Files in server:", files)
            elif choice == '2':
                break
            else:
                print("Invalid choice!")


class KMS:
    def __init__(self):
        self.keys = {}

    def request_key(self, id):
        if id not in self.keys:
            self.keys[id] = Fernet.generate_key()
        return self.keys[id]

    def kms_cli(self):
        while True:
            print("\nCommands:")
            print("1. Exit")
            choice = input("Enter your choice: ")

            if choice == '1':
                break
            else:
                print("Invalid choice!")


# Usage
kms = KMS()
server = Server(MASTER_KEY)
client = Client(server, kms)

print("Client CLI:")
client.client_cli()

print("\nServer CLI:")
server.server_cli()

print("\nKMS CLI:")
kms.kms_cli()
