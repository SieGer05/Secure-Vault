import os
import argparse
import base64
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidKey
from cryptography.fernet import InvalidToken

RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
YELLOW = "\033[33m"
RESET = "\033[0m"

LOGO = """
\t⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀
\t⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀
\t⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀
\t⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
\t⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀
\t⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣠⣤⣤⣼⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀
\t⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀
\t⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀
\t⠀⠀⠀⠘⣿⣿⣿⣿⠟⠁⠀⠀⠀⠹⣿⣿⣿⣿⣿⠟⠁⠀⠀⠹⣿⣿⡿⠀⠀⠀⠀⠀⠀-mao ;3
\t⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⠀⢼⣿⠀⢿⣿⣿⣿⣿⠀⣾⣷⠀⠀⢿⣿⣷⠀⠀⠀⠀⠀⠀
\t⠀⠀⠀⢠⣿⣿⣿⣷⡀⠀⠀⠈⠋⢀⣿⣿⣿⣿⣿⡀⠙⠋⠀⢀⣾⣿⣿⠀⠀⠀⠀⠀⠀
\t⢀⣀⣀⣀⣿⣿⣿⣿⣿⣶⣶⣶⣶⣿⣿⣿⣿⣾⣿⣷⣦⣤⣴⣿⣿⣿⣿⣤⠤⢤⣤⡄⠀
\t⠈⠉⠉⢉⣙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⣀⣀⣀⡀⠀⠀
\t⠐⠚⠋⠉⢀⣬⡿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣥⣀⡀⠈⠀⠈⠛⠀
\t⠀⠀⠴⠚⠉⠀⠀⠀⠉⠛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠋⠁⠀⠀⠀⠉⠛⠢⠀⠀⠀
\t⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
\t⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
\t⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
\t⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
\t⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
\t⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
\t⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀
\t⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

class SecureVault:
   def __init__(self, password, folder_path):
      self.password = password.encode()
      self.folder_path = os.path.abspath(folder_path)
      self.salt_file = os.path.join(folder_path, ".vault_salt")
      self.marker_file = os.path.join(folder_path, ".vault_marker")
      self.fernet = None

   def _generate_key(self, salt=None):
      """Generate encryption key with PBKDF2HMAC"""
      if salt is None:
         salt = os.urandom(16)
         with open(self.salt_file, "wb") as f:
            f.write(salt)
      else:
         salt = salt

      kdf = PBKDF2HMAC(
         algorithm=hashes.SHA256(),
         length=32,
         salt=salt,
         iterations=600000  
      )
      key = base64.urlsafe_b64encode(kdf.derive(self.password))
      self.fernet = Fernet(key)

   def _validate_folder(self):
      """Validate folder state"""
      if not os.path.isdir(self.folder_path):
         raise ValueError(f"{RED}Invalid directory: {self.folder_path}{RESET}")
         
      if len(os.listdir(self.folder_path)) == 0:
         raise ValueError(f"{YELLOW}Folder is empty{RESET}")

   def _process_file(self, file_path, encrypt=True):
      """Secure file processing with temp files"""
      temp_path = file_path + ".tmp"
      try:
         with open(file_path, "rb") as f:
            data = f.read()

         result = self.fernet.encrypt(data) if encrypt else self.fernet.decrypt(data)

         with open(temp_path, "wb") as f:
            f.write(result)

         os.replace(temp_path, file_path)
         return True
      except (InvalidKey, InvalidToken):
         print(f"{RED}❌ Invalid password or corrupted data{RESET}")
         if os.path.exists(temp_path):
               os.remove(temp_path)
         raise SystemExit(1)
      except Exception as e:
         print(f"{RED}❌ Error processing {file_path}: {e}{RESET}")
         return False

   def _handle_filenames(self, file_path, encrypt=True):
      """Encrypt/decrypt filenames securely"""
      dir_name, file_name = os.path.split(file_path)
      try:
         if encrypt:
            new_name = self.fernet.encrypt(file_name.encode()).decode()
         else:
            new_name = self.fernet.decrypt(file_name.encode()).decode()
         return os.path.join(dir_name, new_name)
      except (InvalidKey, InvalidToken):
         print(f"{RED}❌ Invalid password or corrupted filenames{RESET}")
         raise SystemExit(1)

   def encrypt(self):
      """Main encryption flow"""
      try:
         self._validate_folder()
         if os.path.exists(self.marker_file):
            print(f"{YELLOW}⚠️ Folder already encrypted{RESET}")
            return

         self._generate_key()
         open(self.marker_file, "w").close()  # Create marker

         for root, dirs, files in os.walk(self.folder_path):
            for name in list(dirs) + files:
               original_path = os.path.join(root, name)
               if name in [".vault_salt", ".vault_marker"]:
                  continue

               new_path = self._handle_filenames(original_path, encrypt=True)
               os.rename(original_path, new_path)

               if os.path.isfile(new_path):
                  if self._process_file(new_path, encrypt=True):
                     print(f"{GREEN}🔒 Encrypted: {name} → {os.path.basename(new_path)}{RESET}")

         print(f"{GREEN}✅ Encryption successful{RESET}")

      except Exception as e:
         print(f"{RED}❌ Encryption failed: {e}{RESET}")
         raise SystemExit(1)

   def decrypt(self):
      """Main decryption flow"""
      try:
         self._validate_folder()
         if not os.path.exists(self.marker_file):
            print(f"{YELLOW}⚠️ Folder not encrypted{RESET}")
            return

         with open(self.salt_file, "rb") as f:
               salt = f.read()
         self._generate_key(salt)

         for root, dirs, files in os.walk(self.folder_path, topdown=False):
            for name in files + dirs:
               encrypted_path = os.path.join(root, name)
               if name in [".vault_salt", ".vault_marker"]:
                  continue

               if os.path.isfile(encrypted_path):
                  if self._process_file(encrypted_path, encrypt=False):
                     print(f"{GREEN}🔓 Decrypted content: {name}{RESET}")

               original_path = self._handle_filenames(encrypted_path, encrypt=False)
               os.rename(encrypted_path, original_path)
               print(f"{GREEN}🔓 Revealed name: {name} → {os.path.basename(original_path)}{RESET}")

         os.remove(self.salt_file)
         os.remove(self.marker_file)
         print(f"{GREEN}✅ Decryption successful{RESET}")

      except Exception as e:
         print(f"{RED}❌ Decryption failed: {e}{RESET}")
         raise SystemExit(1)

def main():
   print(f"{RED}{LOGO}{RESET}")
   print(f"{GREEN}--- SecureVault : Military Grade Encryption ---{RESET}\n")

   parser = argparse.ArgumentParser(description="Folder encryption tool")
   parser.add_argument("path", help="Path to target folder")
   parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Operation mode")
   args = parser.parse_args()

   password = getpass(f"{BLUE}Enter encryption password: {RESET}")
   confirm = getpass(f"{BLUE}Confirm password: {RESET}")
   if password != confirm:
      print(f"{RED}❌ Passwords don't match{RESET}")
      raise SystemExit(1)

   vault = SecureVault(password, args.path)
   
   try:
      if args.mode == "encrypt":
         vault.encrypt()
      else:
         vault.decrypt()
   except KeyboardInterrupt:
      print(f"\n{RED}🚫 Operation cancelled{RESET}")

if __name__ == "__main__":
   os.system('cls' if os.name == 'nt' else 'clear')
   main()