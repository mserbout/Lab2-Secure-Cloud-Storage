import sys
import subprocess

def run_server():
    subprocess.run(["python", "server-side.py"])

def run_client():
    subprocess.run(["python", "client_side.py"])

if __name__ == "__main__":
    print("Choose mode :")
    print("1. Server-side")
    print("2. Client-side")

    choice = input("Enter your choice (1 or 2): ")

    if choice == "1":
        run_server()

    elif choice == "2":
        run_client()

    else:
        print("Invalid choice. Please enter 1 or 2.")
        sys.exit(1)
