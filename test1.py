from cryptography.fernet import Fernet
import os

# Generate a key for encryption and decryption
MASTER_KEY = Fernet.generate_key()  
PASSWORD = "12345"
class ModeSelector:
    def select_mode():
        while True:
            print("Choose mode:")
            print("1. Clien t")
            print("2. server")
            mode_choice = input("Enter your choice (1 or 2): ")
            if mode_choice == '1':
                return client.client_cli()
            elif mode_choice == '2':
                return 'server'
            else:
                print("Invalid choice! Please enter 1 for server mode or 2 for client mode.")


class Client:
    def __init__(self, server, kms):
        self.server = server
        self.kms = kms

    def upload(self, filename):
        with open(filename, 'rb') as f:
            data = f.read()
        password = input("Enter password to protect the file: ")
        
        if password==PASSWORD:
                dek = self.kms.request_key(filename)  # Request DEK from KMS
                #encrypt the DEK
                encrypted_dek = self.kms.encrypt_key(dek, password)
                #encrypt the data with the DEK
                cipher_suite = Fernet(dek)
                encrypted_data = cipher_suite.encrypt(data)
                #store the encrypted DEK and data on the server
                self.server.store(filename, encrypted_data, encrypted_dek)
        else:
                print("INCORRECT PASSWORD")

    def download(self, filename, output_filename):
        encrypted_dek, encrypted_data = self.server.retrieve(filename)
        if encrypted_data:
            password = input("Enter password to decrypt the file: ")
            if password==PASSWORD:   
                    # Decrypt the DEK with Master Key and password
                    dek = self.kms.decrypt_key(encrypted_dek, password)

                    # dek = self.kms.request_key(filename)  # Request DEK from KMS
                    cipher_suite = Fernet(dek)
                    decrypted_data = cipher_suite.decrypt(encrypted_data)
                    with open(output_filename, 'wb') as f:
                        f.write(decrypted_data)
                    print("File downloaded successfully!")
            else:
                    print("INCORRECT PASSWORD")

        else:
            print("File not found!")


    # def download(self, filename, output_filename):
    #     encrypted_dek, encrypted_data = self.server.retrieve(filename)
    #     if encrypted_data:
    #         #encrypted_dek, encrypted_data = result
    #         password = input("Enter password to decrypt the file: ")
    #         if password==PASSWORD:
    #             dek = self.kms.decrypt_key(encrypted_dek, password)
    #             if dek is not None:
    #                 cipher_suite = Fernet(dek)
    #                 decrypted_data = cipher_suite.decrypt(encrypted_data)
    #                 with open(output_filename, 'wb') as f:
    #                     f.write(decrypted_data)
    #                 print("File downloaded successfully!")
    #             else:
    #                 print("Incorrect password!")
    #         else:
    #             print("Incorrect password!")
    #     else:
    #         print("File not found!")
    # def download(self, filename, output_filename):
    #     encrypted_dek, encrypted_data = self.server.retrieve(filename)
    #     if encrypted_data:
    #         password = input("Enter password to decrypt the file: ")
    #         print("Password entered:", password)
    #         if password == PASSWORD:
    #             print("Correct password entered.")
    #             dek = self.kms.decrypt_key(encrypted_dek, password)
    #             print("Decrypted DEK:", dek)
    #             if dek is not None:
    #                 cipher_suite = Fernet(dek)
    #                 decrypted_data = cipher_suite.decrypt(encrypted_data)
    #                 with open(output_filename, 'wb') as f:
    #                     f.write(decrypted_data)
    #                 print("File downloaded successfully!")
    #             else:
    #                 print("Incorrect password!")
    #         else:
    #             print("Incorrect password!")
    #     else:
    #         print("File not found!")


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
        self.cipher_suite = Fernet(master_key)  # Initialize Fernet instance


    def store(self, filename, encrypted_data, encrypted_dek):
        # Server-side encryption using Customer Master Key
        cipher_suite = Fernet(self.master_key)
        encrypted_data = cipher_suite.encrypt(encrypted_data)
        encrypted_data1 = bytes(encrypted_data)
        encrypted_dek1 = bytes(encrypted_dek)
        self.storage[filename] = (encrypted_data1, encrypted_dek1)

    #def retrieve(self, filename):
        # Server-side decryption using Customer Master Key
        # if filename in self.storage:
        #     encrypted_data, encrypted_dek = self.storage[filename]
        #     cipher_suite = Fernet(self.master_key)
        #     encrypted_data = bytes(encrypted_data)
        #     encrypted_dek = bytes(encrypted_dek)
        #     return encrypted_data,encrypted_dek
        # else:
        #     return None
    def retrieve(self, filename):
    # Server-side decryption using Customer Master Key
        if filename in self.storage:
            return self.storage[filename]
        else:
            return None


    def list_files(self):
        return list(self.storage.keys())

    # def server_cli(self):
    #     while True:
    #         print("\nCommands:")
    #         print("1. List files")
    #         print("2. Exit")
    #         choice = input("Enter your choice: ")

    #         if choice == '1':
    #             files = self.list_files()
    #             print("Files in server:", files)
    #         elif choice == '2':
    #             break
    #         else:
    #             print("Invalid choice!")


class KMS:
    def __init__(self):
        self.keys = {}
        self.key_hierarchy = {}  # Add key_hierarchy attribute

    def request_key(self, id):
        if id not in self.keys:
            self.keys[id] = Fernet.generate_key()
        return self.keys[id]

    def encrypt_key(self, key, password):
        kek = Fernet.generate_key()
        cipher_suite = Fernet(kek)
        encrypted_key = cipher_suite.encrypt(key)
        mk = Fernet(MASTER_KEY)
        encrypted_kek = mk.encrypt(kek)
        self.key_hierarchy[encrypted_key] = (encrypted_kek, password)
        return encrypted_key

    def decrypt_key(self, encrypted_key, password):
        mk = Fernet(MASTER_KEY)
        kek, stored_password = self.key_hierarchy.get(encrypted_key, (None, None))
        if kek and stored_password == password:
            kek = mk.decrypt(kek)
            cipher_suite = Fernet(kek)
            return cipher_suite.decrypt(encrypted_key)
        else:
            return None

    # def kms_cli(self):
    #     while True:
    #         print("\nCommands:")
    #         print("1. Exit")
    #         choice = input("Enter your choice: ")

    #         if choice == '1':
    #             break
    #         else:
    #             print("Invalid choice!")


# Usage
kms = KMS()
server = Server(MASTER_KEY)
client = Client(server, kms)

ModeSelector.select_mode()

# print("Client CLI:")
# client.client_cli()

# print("\nServer CLI:")
# server.server_cli()

# print("\nKMS CLI:")
# kms.kms_cli()
