from cryptography.fernet import Fernet
import os
import secrets

  
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
        self.key_hierarchy = {}  

    def upload(self, filename):
        with open(filename, 'rb') as f:
            data = f.read()
        
        password = input("Enter password to protect the file: ")
        if password==PASSWORD:   
            # Request DEK from KMS
            dek = self.kms.request_key(filename)  
            cipher_suite = Fernet(dek)
            encrypted_data = cipher_suite.encrypt(data)
            #generate KEK
            kek=self.kms.request_key(dek) 
            # Encrypt DEK with KEK
            kek_cipher_suite = Fernet(kek)
            encrypted_dek = kek_cipher_suite.encrypt(dek)
            #generate MASTER_KEY
            MK=self.kms.request_key(kek) 
            #Encrypt KEK with MASTER_KEY
            MK_cipher_suite = Fernet(MK)
            encrypted_kek = MK_cipher_suite.encrypt(kek)
            self.key_hierarchy[encrypted_dek] = (encrypted_kek, password)
            # Add file metadata to encrypted data
            metadata = {
                'filename': filename,
                'key_id': encrypted_dek
            }

            encrypted_data_with_metadata = {
                'data': encrypted_data,
                'metadata': metadata
            }

            # print(f"encrypted data {encrypted_data} ")
            # print(f"-------------------------------------------------------------------------------------------------------------------")

            print(f"encrypted_dek {encrypted_dek}")
            # print(f"-------------------------------------------------------------------------------------------------------------------")

            print(f"encrypted_kek{encrypted_kek}")
            # print(f"-------------------------------------------------------------------------------------------------------------------")
            print(f"mk {MK}")


            self.server.store(filename,encrypted_data_with_metadata,encrypted_kek,MK)
            print("File uploaded successfully!")
        else:
                print("INCORRECT PASSWORD")


    def download(self, filename, output_filename):
        encrypted_data_with_metadata = self.server.retrieve(filename)

        if encrypted_data_with_metadata:
           
            encrypted_kek = encrypted_data_with_metadata['encrypted_kek']
            encrypted_data = encrypted_data_with_metadata['encrypted_data_with_metadata']['data']
            encrypted_dek = encrypted_data_with_metadata['encrypted_data_with_metadata']['metadata']['key_id']
            MK = encrypted_data_with_metadata['MK']

         
            password = input("Enter your password: ")
            if password==PASSWORD:
                #decrypt KEK with the master key
                MK_cipher_suite = Fernet(MK)
                decrypted_kek = MK_cipher_suite.decrypt(encrypted_kek)
                # Decrypt the DEK with KEK
                decrypted_kek_cipher_suite = Fernet(decrypted_kek)
                decrypted_dek = decrypted_kek_cipher_suite.decrypt(encrypted_dek)
                # Decrypt the data using DEK
                dek_cipher_suite = Fernet(decrypted_dek)
                decrypted_data = dek_cipher_suite.decrypt(encrypted_data)
                with open(output_filename, 'wb') as f:
                    f.write(decrypted_data)
                print("File downloaded successfully!")

                # Securely delete keys after decryption
                self.kms.secure_delete_key(decrypted_dek)
                self.kms.secure_delete_key(decrypted_kek)
                self.kms.secure_delete_key(MK)

                print("---------------------------------")

                print(decrypted_dek)
              
                print("---------------------------------")

                print(decrypted_kek)
                print("---------------------------------")

                print(MK)

            else:
                print("INCORRECT PASSWORD")
            
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
    def __init__(self):
        self.storage = {}

    def store(self, filename,encrypted_data_with_metadata,encrypted_kek,MK):

        self.storage[filename] = {
            'encrypted_data_with_metadata': encrypted_data_with_metadata,
            'encrypted_kek': encrypted_kek,
            'MK':MK
        }


    def retrieve(self, filename):
        if filename in self.storage:
            return self.storage[filename]
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


    def secure_delete_key(self, key_id):
        if key_id in self.keys:
            key_length = len(self.keys[key_id])
            self.keys[key_id] = secrets.token_bytes(key_length)




kms = KMS()
server = Server()
client = Client(server, kms)

ModeSelector.select_mode()

print("Client CLI:")
client.client_cli()

print("\nServer CLI:")
server.server_cli()
