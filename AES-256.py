from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import getpass
import sys

class AdvancedEncryptionTool:
    def __init__(self):
        self.backend = default_backend()
        self.block_size = 128
        
    def derive_key(self, password, salt):
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())
    
    def encrypt_data(self, data, password):
        salt = os.urandom(16)
        iv = os.urandom(16)
        
        key = self.derive_key(password, salt)
        
        padder = padding.PKCS7(self.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        result = salt + iv + encrypted_data
        return base64.b64encode(result)
    
    def decrypt_data(self, encrypted_data, password):
        try:
            encrypted_data = base64.b64decode(encrypted_data)
            
            salt = encrypted_data[:16]
            iv = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            
            key = self.derive_key(password, salt)
            
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            unpadder = padding.PKCS7(self.block_size).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            
            return data
        except Exception as e:
            raise ValueError("Decryption failed. Incorrect password or corrupted data.")
    
    def encrypt_file(self, input_file, output_file, password):
        try:
            with open(input_file, 'rb') as f:
                file_data = f.read()
            
            encrypted_data = self.encrypt_data(file_data, password)
            
            with open(output_file, 'wb') as f:
                f.write(encrypted_data)
            
            print(f"[+] File encrypted successfully: {output_file}")
            return True
        except FileNotFoundError:
            print(f"[!] Error: File '{input_file}' not found")
            return False
        except Exception as e:
            print(f"[!] Encryption error: {str(e)}")
            return False
    
    def decrypt_file(self, input_file, output_file, password):
        try:
            with open(input_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.decrypt_data(encrypted_data, password)
            
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
            
            print(f"[+] File decrypted successfully: {output_file}")
            return True
        except FileNotFoundError:
            print(f"[!] Error: File '{input_file}' not found")
            return False
        except ValueError as e:
            print(f"[!] {str(e)}")
            return False
        except Exception as e:
            print(f"[!] Decryption error: {str(e)}")
            return False
    
    def encrypt_text(self, text, password):
        encrypted = self.encrypt_data(text.encode(), password)
        return encrypted.decode()
    
    def decrypt_text(self, encrypted_text, password):
        decrypted = sealf.decrypt_data(encrypted_text.encode(), password)
        return decrypted.decode()

def display_banner():
    banner = """
    ╔═══════════════════════════════════════════════════╗
    ║     ADVANCED ENCRYPTION TOOL -                    ║
    ║              AES-256 Encryption                   ║
    ║                                                   ║
    ╚═══════════════════════════════════════════════════╝
    """
    print(banner)

def display_menu():
    print("\n" + "="*50)
    print("           ENCRYPTION TOOL MENU")
    print("="*50)
    print("1. Encrypt File")
    print("2. Decrypt File")
    print("3. Encrypt Text")
    print("4. Decrypt Text")
    print("5. Exit")
    print("="*50)

def encrypt_file_mode(tool):
    print("\n--- FILE ENCRYPTION MODE ---")
    input_file = input("Enter input file path: ").strip()
    output_file = input("Enter output file path (encrypted): ").strip()
    
    if not output_file:
        output_file = input_file + ".encrypted"
    
    password = getpass.getpass("Enter encryption password: ")
    confirm_password = getpass.getpass("Confirm password: ")
    
    if password != confirm_password:
        print("[!] Passwords do not match!")
        return
    
    if len(password) < 8:
        print("[!] Password must be at least 8 characters long")
        return
    
    print("\n[*] Encrypting file...")
    tool.encrypt_file(input_file, output_file, password)

def decrypt_file_mode(tool):
    print("\n--- FILE DECRYPTION MODE ---")
    input_file = input("Enter encrypted file path: ").strip()
    output_file = input("Enter output file path (decrypted): ").strip()
    
    if not output_file:
        output_file = input_file.replace(".encrypted", ".decrypted")
    
    password = getpass.getpass("Enter decryption password: ")
    
    print("\n[*] Decrypting file...")
    tool.decrypt_file(input_file, output_file, password)

def encrypt_text_mode(tool):
    print("\n--- TEXT ENCRYPTION MODE ---")
    text = input("Enter text to encrypt: ")
    password = getpass.getpass("Enter encryption password: ")
    confirm_password = getpass.getpass("Confirm password: ")
    
    if password != confirm_password:
        print("[!] Passwords do not match!")
        return
    
    if len(password) < 8:
        print("[!] Password must be at least 8 characters long")
        return
    
    print("\n[*] Encrypting text...")
    encrypted = tool.encrypt_text(text, password)
    print(f"\n[+] Encrypted text:\n{encrypted}")

def decrypt_text_mode(tool):
    print("\n--- TEXT DECRYPTION MODE ---")
    encrypted_text = input("Enter encrypted text: ")
    password = getpass.getpass("Enter decryption password: ")
    
    print("\n[*] Decrypting text...")
    try:
        decrypted = tool.decrypt_text(encrypted_text, password)
        print(f"\n[+] Decrypted text:\n{decrypted}")
    except Exception as e:
        print(f"[!] Decryption failed: {str(e)}")

def main():
    display_banner()
    tool = AdvancedEncryptionTool()
    
    while True:
        display_menu()
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == '1':
            encrypt_file_mode(tool)
        elif choice == '2':
            decrypt_file_mode(tool)
        elif choice == '3':
            encrypt_text_mode(tool)
        elif choice == '4':
            decrypt_text_mode(tool)
        elif choice == '5':
            print("\n[*] Thank you for using Advanced Encryption Tool!")
            print("[*] CodTech Solutions - Internship Task 4")
            sys.exit(0)
        else:
            print("[!] Invalid choice. Please select 1-5.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Program interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Unexpected error: {str(e)}")
        sys.exit(1)