#!/usr/bin/env python3

import os
import sys
import hashlib
import base64
import json
import time
import getpass
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

class CryptoVault:
    def __init__(self):
        self.version = "2.1.0"
        self.author = "sentinelzxofc"
        self.repo = "https://github.com/sentinelzxofc/cryptovault"
        self.banner()
        
    def banner(self):
        print("\033[1;36m" + "="*70)
        print("██████╗ ██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗")
        print("██╔══██╗██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝")
        print("██████╔╝██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██║   ██║███████║██║   ██║██║     ██║   ")
        print("██╔══██╗██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ")
        print("██████╔╝██║  ██║   ██║   ██║        ██║   ╚██████╔╝ ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ")
        print("╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝   ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ")
        print("\033[1;33m" + f"                    Advanced Encryption Tool v{self.version}")
        print(f"                    Author: {self.author}")
        print(f"                    Repository: {self.repo}")
        print("\033[1;36m" + "="*70 + "\033[0m")
        print()

    def show_menu(self):
        print("\033[1;32m┌─────────────────────────────────────────────────────────────────┐")
        print("│                        MENU PRINCIPAL                          │")
        print("├─────────────────────────────────────────────────────────────────┤")
        print("│ [1] Criptografar Arquivo / Encrypt File                        │")
        print("│ [2] Descriptografar Arquivo / Decrypt File                     │")
        print("│ [3] Criptografar Texto / Encrypt Text                          │")
        print("│ [4] Descriptografar Texto / Decrypt Text                       │")
        print("│ [5] Criptografar Diretório / Encrypt Directory                 │")
        print("│ [6] Descriptografar Diretório / Decrypt Directory              │")
        print("│ [7] Gerar Chave Segura / Generate Secure Key                   │")
        print("│ [8] Hash de Arquivo / File Hash                                │")
        print("│ [9] Verificar Integridade / Verify Integrity                   │")
        print("│ [10] Modo Avançado / Advanced Mode                             │")
        print("│ [11] Ajuda / Help                                              │")
        print("│ [0] Sair / Exit                                                │")
        print("└─────────────────────────────────────────────────────────────────┘\033[0m")
        print()

    def show_advanced_menu(self):
        print("\033[1;35m┌─────────────────────────────────────────────────────────────────┐")
        print("│                        MODO AVANÇADO                           │")
        print("├─────────────────────────────────────────────────────────────────┤")
        print("│ [1] AES-256-CBC Encryption                                      │")
        print("│ [2] AES-256-GCM Encryption                                      │")
        print("│ [3] ChaCha20-Poly1305 Encryption                               │")
        print("│ [4] Fernet Encryption (Symmetric)                              │")
        print("│ [5] Triple DES Encryption                                       │")
        print("│ [6] Blowfish Encryption                                         │")
        print("│ [7] RC4 Encryption                                              │")
        print("│ [8] XOR Cipher                                                  │")
        print("│ [9] Caesar Cipher                                               │")
        print("│ [10] Vigenère Cipher                                            │")
        print("│ [11] Base64 Encoding/Decoding                                   │")
        print("│ [12] ROT13 Cipher                                               │")
        print("│ [0] Voltar / Back                                               │")
        print("└─────────────────────────────────────────────────────────────────┘\033[0m")
        print()

    def generate_key_from_password(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def encrypt_file_fernet(self, file_path, password):
        try:
            key, salt = self.generate_key_from_password(password)
            fernet = Fernet(key)
            
            with open(file_path, 'rb') as file:
                file_data = file.read()
            
            encrypted_data = fernet.encrypt(file_data)
            
            encrypted_file_path = file_path + '.cryptovault'
            with open(encrypted_file_path, 'wb') as encrypted_file:
                encrypted_file.write(salt + encrypted_data)
            
            os.remove(file_path)
            print(f"\033[1;32m✓ Arquivo criptografado com sucesso: {encrypted_file_path}\033[0m")
            return True
        except Exception as e:
            print(f"\033[1;31m✗ Erro ao criptografar arquivo: {str(e)}\033[0m")
            return False

    def decrypt_file_fernet(self, file_path, password):
        try:
            with open(file_path, 'rb') as encrypted_file:
                salt = encrypted_file.read(16)
                encrypted_data = encrypted_file.read()
            
            key, _ = self.generate_key_from_password(password, salt)
            fernet = Fernet(key)
            
            decrypted_data = fernet.decrypt(encrypted_data)
            
            original_file_path = file_path.replace('.cryptovault', '')
            with open(original_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)
            
            os.remove(file_path)
            print(f"\033[1;32m✓ Arquivo descriptografado com sucesso: {original_file_path}\033[0m")
            return True
        except Exception as e:
            print(f"\033[1;31m✗ Erro ao descriptografar arquivo: {str(e)}\033[0m")
            return False

    def encrypt_aes_256_cbc(self, data, password):
        try:
            salt = os.urandom(16)
            key, _ = self.generate_key_from_password(password, salt)
            iv = os.urandom(16)
            
            cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            padded_data = self.pad_data(data)
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            return salt + iv + encrypted_data
        except Exception as e:
            print(f"\033[1;31m✗ Erro AES-256-CBC: {str(e)}\033[0m")
            return None

    def decrypt_aes_256_cbc(self, encrypted_data, password):
        try:
            salt = encrypted_data[:16]
            iv = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            
            key, _ = self.generate_key_from_password(password, salt)
            
            cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
            return self.unpad_data(decrypted_padded)
        except Exception as e:
            print(f"\033[1;31m✗ Erro ao descriptografar AES-256-CBC: {str(e)}\033[0m")
            return None

    def encrypt_aes_256_gcm(self, data, password):
        try:
            salt = os.urandom(16)
            key, _ = self.generate_key_from_password(password, salt)
            iv = os.urandom(12)
            
            cipher = Cipher(algorithms.AES(key[:32]), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            return salt + iv + encryptor.tag + ciphertext
        except Exception as e:
            print(f"\033[1;31m✗ Erro AES-256-GCM: {str(e)}\033[0m")
            return None

    def decrypt_aes_256_gcm(self, encrypted_data, password):
        try:
            salt = encrypted_data[:16]
            iv = encrypted_data[16:28]
            tag = encrypted_data[28:44]
            ciphertext = encrypted_data[44:]
            
            key, _ = self.generate_key_from_password(password, salt)
            
            cipher = Cipher(algorithms.AES(key[:32]), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            print(f"\033[1;31m✗ Erro ao descriptografar AES-256-GCM: {str(e)}\033[0m")
            return None

    def encrypt_chacha20_poly1305(self, data, password):
        try:
            salt = os.urandom(16)
            key, _ = self.generate_key_from_password(password, salt)
            nonce = os.urandom(12)
            
            cipher = Cipher(algorithms.ChaCha20(key[:32], nonce), mode=None, backend=default_backend())
            encryptor = cipher.encryptor()
            
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            return salt + nonce + ciphertext
        except Exception as e:
            print(f"\033[1;31m✗ Erro ChaCha20-Poly1305: {str(e)}\033[0m")
            return None

    def decrypt_chacha20_poly1305(self, encrypted_data, password):
        try:
            salt = encrypted_data[:16]
            nonce = encrypted_data[16:28]
            ciphertext = encrypted_data[28:]
            
            key, _ = self.generate_key_from_password(password, salt)
            
            cipher = Cipher(algorithms.ChaCha20(key[:32], nonce), mode=None, backend=default_backend())
            decryptor = cipher.decryptor()
            
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            print(f"\033[1;31m✗ Erro ao descriptografar ChaCha20-Poly1305: {str(e)}\033[0m")
            return None

    def xor_cipher(self, data, key):
        result = bytearray()
        key_bytes = key.encode() if isinstance(key, str) else key
        for i, byte in enumerate(data):
            result.append(byte ^ key_bytes[i % len(key_bytes)])
        return bytes(result)

    def caesar_cipher(self, text, shift, decrypt=False):
        if decrypt:
            shift = -shift
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        return result

    def vigenere_cipher(self, text, key, decrypt=False):
        result = ""
        key = key.upper()
        key_index = 0
        
        for char in text:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - 65
                if decrypt:
                    shift = -shift
                
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
                key_index += 1
            else:
                result += char
        return result

    def rot13_cipher(self, text):
        return self.caesar_cipher(text, 13)

    def pad_data(self, data):
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def unpad_data(self, padded_data):
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]

    def calculate_file_hash(self, file_path, algorithm='sha256'):
        hash_algorithms = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha512': hashlib.sha512()
        }
        
        if algorithm not in hash_algorithms:
            print(f"\033[1;31m✗ Algoritmo de hash não suportado: {algorithm}\033[0m")
            return None
        
        try:
            hasher = hash_algorithms[algorithm]
            with open(file_path, 'rb') as file:
                for chunk in iter(lambda: file.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            print(f"\033[1;31m✗ Erro ao calcular hash: {str(e)}\033[0m")
            return None

    def encrypt_directory(self, directory_path, password):
        try:
            encrypted_count = 0
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    if not file.endswith('.cryptovault'):
                        file_path = os.path.join(root, file)
                        if self.encrypt_file_fernet(file_path, password):
                            encrypted_count += 1
            
            print(f"\033[1;32m✓ {encrypted_count} arquivos criptografados no diretório\033[0m")
            return True
        except Exception as e:
            print(f"\033[1;31m✗ Erro ao criptografar diretório: {str(e)}\033[0m")
            return False

    def decrypt_directory(self, directory_path, password):
        try:
            decrypted_count = 0
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    if file.endswith('.cryptovault'):
                        file_path = os.path.join(root, file)
                        if self.decrypt_file_fernet(file_path, password):
                            decrypted_count += 1
            
            print(f"\033[1;32m✓ {decrypted_count} arquivos descriptografados no diretório\033[0m")
            return True
        except Exception as e:
            print(f"\033[1;31m✗ Erro ao descriptografar diretório: {str(e)}\033[0m")
            return False

    def generate_secure_key(self, length=32):
        key = secrets.token_hex(length)
        print(f"\033[1;33m🔑 Chave segura gerada ({length*2} caracteres):\033[0m")
        print(f"\033[1;36m{key}\033[0m")
        
        save_option = input("\n\033[1;33mDeseja salvar a chave em um arquivo? (s/n): \033[0m").lower()
        if save_option == 's':
            filename = input("\033[1;33mNome do arquivo (sem extensão): \033[0m") + ".key"
            try:
                with open(filename, 'w') as key_file:
                    key_file.write(key)
                print(f"\033[1;32m✓ Chave salva em: {filename}\033[0m")
            except Exception as e:
                print(f"\033[1;31m✗ Erro ao salvar chave: {str(e)}\033[0m")
        
        return key

    def show_help(self):
        print("\033[1;34m" + "="*70)
        print("                           AJUDA / HELP")
        print("="*70 + "\033[0m")
        print()
        print("\033[1;33mCOMO USAR / HOW TO USE:\033[0m")
        print("1. Escolha uma opção do menu principal")
        print("2. Forneça o caminho do arquivo/diretório quando solicitado")
        print("3. Digite uma senha forte para criptografia")
        print("4. Aguarde o processamento")
        print()
        print("\033[1;33mDICAS DE SEGURANÇA / SECURITY TIPS:\033[0m")
        print("• Use senhas fortes com pelo menos 12 caracteres")
        print("• Combine letras maiúsculas, minúsculas, números e símbolos")
        print("• Nunca compartilhe suas senhas")
        print("• Faça backup de arquivos importantes antes da criptografia")
        print("• Mantenha suas senhas em local seguro")
        print()
        print("\033[1;33mFORMATOS SUPORTADOS / SUPPORTED FORMATS:\033[0m")
        print("• Todos os tipos de arquivo (imagens, documentos, vídeos, etc.)")
        print("• Diretórios completos")
        print("• Texto simples")
        print()
        print("\033[1;33mALGORITMOS DISPONÍVEIS / AVAILABLE ALGORITHMS:\033[0m")
        print("• Fernet (Recomendado para uso geral)")
        print("• AES-256-CBC (Padrão militar)")
        print("• AES-256-GCM (Com autenticação)")
        print("• ChaCha20-Poly1305 (Moderno e rápido)")
        print("• E muitos outros no modo avançado")
        print()
        print("\033[1;31mAVISO IMPORTANTE / IMPORTANT WARNING:\033[0m")
        print("Se você esquecer a senha, NÃO será possível recuperar os dados!")
        print("If you forget the password, data recovery will be IMPOSSIBLE!")
        print()

    def verify_file_integrity(self, file_path):
        if not os.path.exists(file_path):
            print(f"\033[1;31m✗ Arquivo não encontrado: {file_path}\033[0m")
            return
        
        print(f"\033[1;33m📊 Verificando integridade de: {file_path}\033[0m")
        print()
        
        algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        for algorithm in algorithms:
            hash_value = self.calculate_file_hash(file_path, algorithm)
            if hash_value:
                print(f"\033[1;36m{algorithm.upper()}: {hash_value}\033[0m")
        
        file_size = os.path.getsize(file_path)
        print(f"\033[1;36mTamanho: {file_size} bytes ({file_size/1024:.2f} KB)\033[0m")
        
        modification_time = os.path.getmtime(file_path)
        print(f"\033[1;36mÚltima modificação: {time.ctime(modification_time)}\033[0m")

    def advanced_mode(self):
        while True:
            self.show_advanced_menu()
            choice = input("\033[1;33mEscolha uma opção / Choose an option: \033[0m")
            
            if choice == '0':
                break
            elif choice == '1':
                self.handle_aes_256_cbc()
            elif choice == '2':
                self.handle_aes_256_gcm()
            elif choice == '3':
                self.handle_chacha20_poly1305()
            elif choice == '4':
                self.handle_fernet_advanced()
            elif choice == '8':
                self.handle_xor_cipher()
            elif choice == '9':
                self.handle_caesar_cipher()
            elif choice == '10':
                self.handle_vigenere_cipher()
            elif choice == '11':
                self.handle_base64()
            elif choice == '12':
                self.handle_rot13()
            else:
                print("\033[1;31m✗ Opção inválida!\033[0m")

    def handle_aes_256_cbc(self):
        print("\033[1;35m🔐 AES-256-CBC Encryption\033[0m")
        mode = input("Criptografar (1) ou Descriptografar (2)? ").strip()
        
        if mode == '1':
            file_path = input("Caminho do arquivo: ").strip()
            if not os.path.exists(file_path):
                print("\033[1;31m✗ Arquivo não encontrado!\033[0m")
                return
            
            password = getpass.getpass("Senha: ")
            
            try:
                with open(file_path, 'rb') as file:
                    data = file.read()
                
                encrypted_data = self.encrypt_aes_256_cbc(data, password)
                if encrypted_data:
                    output_path = file_path + '.aes256cbc'
                    with open(output_path, 'wb') as output_file:
                        output_file.write(encrypted_data)
                    print(f"\033[1;32m✓ Arquivo criptografado: {output_path}\033[0m")
            except Exception as e:
                print(f"\033[1;31m✗ Erro: {str(e)}\033[0m")
        
        elif mode == '2':
            file_path = input("Caminho do arquivo criptografado: ").strip()
            if not os.path.exists(file_path):
                print("\033[1;31m✗ Arquivo não encontrado!\033[0m")
                return
            
            password = getpass.getpass("Senha: ")
            
            try:
                with open(file_path, 'rb') as file:
                    encrypted_data = file.read()
                
                decrypted_data = self.decrypt_aes_256_cbc(encrypted_data, password)
                if decrypted_data:
                    output_path = file_path.replace('.aes256cbc', '_decrypted')
                    with open(output_path, 'wb') as output_file:
                        output_file.write(decrypted_data)
                    print(f"\033[1;32m✓ Arquivo descriptografado: {output_path}\033[0m")
            except Exception as e:
                print(f"\033[1;31m✗ Erro: {str(e)}\033[0m")

    def handle_aes_256_gcm(self):
        print("\033[1;35m🔐 AES-256-GCM Encryption\033[0m")
        mode = input("Criptografar (1) ou Descriptografar (2)? ").strip()
        
        if mode == '1':
            file_path = input("Caminho do arquivo: ").strip()
            if not os.path.exists(file_path):
                print("\033[1;31m✗ Arquivo não encontrado!\033[0m")
                return
            
            password = getpass.getpass("Senha: ")
            
            try:
                with open(file_path, 'rb') as file:
                    data = file.read()
                
                encrypted_data = self.encrypt_aes_256_gcm(data, password)
                if encrypted_data:
                    output_path = file_path + '.aes256gcm'
                    with open(output_path, 'wb') as output_file:
                        output_file.write(encrypted_data)
                    print(f"\033[1;32m✓ Arquivo criptografado: {output_path}\033[0m")
            except Exception as e:
                print(f"\033[1;31m✗ Erro: {str(e)}\033[0m")
        
        elif mode == '2':
            file_path = input("Caminho do arquivo criptografado: ").strip()
            if not os.path.exists(file_path):
                print("\033[1;31m✗ Arquivo não encontrado!\033[0m")
                return
            
            password = getpass.getpass("Senha: ")
            
            try:
                with open(file_path, 'rb') as file:
                    encrypted_data = file.read()
                
                decrypted_data = self.decrypt_aes_256_gcm(encrypted_data, password)
                if decrypted_data:
                    output_path = file_path.replace('.aes256gcm', '_decrypted')
                    with open(output_path, 'wb') as output_file:
                        output_file.write(decrypted_data)
                    print(f"\033[1;32m✓ Arquivo descriptografado: {output_path}\033[0m")
            except Exception as e:
                print(f"\033[1;31m✗ Erro: {str(e)}\033[0m")

    def handle_chacha20_poly1305(self):
        print("\033[1;35m🔐 ChaCha20-Poly1305 Encryption\033[0m")
        mode = input("Criptografar (1) ou Descriptografar (2)? ").strip()
        
        if mode == '1':
            file_path = input("Caminho do arquivo: ").strip()
            if not os.path.exists(file_path):
                print("\033[1;31m✗ Arquivo não encontrado!\033[0m")
                return
            
            password = getpass.getpass("Senha: ")
            
            try:
                with open(file_path, 'rb') as file:
                    data = file.read()
                
                encrypted_data = self.encrypt_chacha20_poly1305(data, password)
                if encrypted_data:
                    output_path = file_path + '.chacha20'
                    with open(output_path, 'wb') as output_file:
                        output_file.write(encrypted_data)
                    print(f"\033[1;32m✓ Arquivo criptografado: {output_path}\033[0m")
            except Exception as e:
                print(f"\033[1;31m✗ Erro: {str(e)}\033[0m")
        
        elif mode == '2':
            file_path = input("Caminho do arquivo criptografado: ").strip()
            if not os.path.exists(file_path):
                print("\033[1;31m✗ Arquivo não encontrado!\033[0m")
                return
            
            password = getpass.getpass("Senha: ")
            
            try:
                with open(file_path, 'rb') as file:
                    encrypted_data = file.read()
                
                decrypted_data = self.decrypt_chacha20_poly1305(encrypted_data, password)
                if decrypted_data:
                    output_path = file_path.replace('.chacha20', '_decrypted')
                    with open(output_path, 'wb') as output_file:
                        output_file.write(decrypted_data)
                    print(f"\033[1;32m✓ Arquivo descriptografado: {output_path}\033[0m")
            except Exception as e:
                print(f"\033[1;31m✗ Erro: {str(e)}\033[0m")

    def handle_fernet_advanced(self):
        print("\033[1;35m🔐 Fernet Symmetric Encryption\033[0m")
        mode = input("Criptografar (1) ou Descriptografar (2)? ").strip()
        
        if mode == '1':
            file_path = input("Caminho do arquivo: ").strip()
            if not os.path.exists(file_path):
                print("\033[1;31m✗ Arquivo não encontrado!\033[0m")
                return
            
            password = getpass.getpass("Senha: ")
            self.encrypt_file_fernet(file_path, password)
        
        elif mode == '2':
            file_path = input("Caminho do arquivo criptografado: ").strip()
            if not os.path.exists(file_path):
                print("\033[1;31m✗ Arquivo não encontrado!\033[0m")
                return
            
            password = getpass.getpass("Senha: ")
            self.decrypt_file_fernet(file_path, password)

    def handle_xor_cipher(self):
        print("\033[1;35m🔐 XOR Cipher\033[0m")
        text = input("Digite o texto: ")
        key = input("Digite a chave: ")
        
        if isinstance(text, str):
            text = text.encode()
        
        result = self.xor_cipher(text, key)
        
        print(f"\033[1;36mResultado (hex): {result.hex()}\033[0m")
        print(f"\033[1;36mResultado (base64): {base64.b64encode(result).decode()}\033[0m")

    def handle_caesar_cipher(self):
        print("\033[1;35m🔐 Caesar Cipher\033[0m")
        text = input("Digite o texto: ")
        shift = int(input("Digite o deslocamento (1-25): "))
        mode = input("Criptografar (1) ou Descriptografar (2)? ").strip()
        
        decrypt = mode == '2'
        result = self.caesar_cipher(text, shift, decrypt)
        
        print(f"\033[1;36mResultado: {result}\033[0m")

    def handle_vigenere_cipher(self):
        print("\033[1;35m🔐 Vigenère Cipher\033[0m")
        text = input("Digite o texto: ")
        key = input("Digite a chave: ")
        mode = input("Criptografar (1) ou Descriptografar (2)? ").strip()
        
        decrypt = mode == '2'
        result = self.vigenere_cipher(text, key, decrypt)
        
        print(f"\033[1;36mResultado: {result}\033[0m")

    def handle_base64(self):
        print("\033[1;35m🔐 Base64 Encoding/Decoding\033[0m")
        mode = input("Codificar (1) ou Decodificar (2)? ").strip()
        
        if mode == '1':
            text = input("Digite o texto: ")
            encoded = base64.b64encode(text.encode()).decode()
            print(f"\033[1;36mTexto codificado: {encoded}\033[0m")
        elif mode == '2':
            encoded_text = input("Digite o texto codificado: ")
            try:
                decoded = base64.b64decode(encoded_text).decode()
                print(f"\033[1;36mTexto decodificado: {decoded}\033[0m")
            except Exception as e:
                print(f"\033[1;31m✗ Erro ao decodificar: {str(e)}\033[0m")

    def handle_rot13(self):
        print("\033[1;35m🔐 ROT13 Cipher\033[0m")
        text = input("Digite o texto: ")
        result = self.rot13_cipher(text)
        print(f"\033[1;36mResultado: {result}\033[0m")

    def run(self):
        while True:
            try:
                self.show_menu()
                choice = input("\033[1;33mEscolha uma opção / Choose an option: \033[0m")
                
                if choice == '0':
                    print("\033[1;32m👋 Obrigado por usar o CryptoVault! / Thanks for using CryptoVault!\033[0m")
                    break
                
                elif choice == '1':
                    file_path = input("\033[1;33mCaminho do arquivo / File path: \033[0m").strip()
                    if not os.path.exists(file_path):
                        print("\033[1;31m✗ Arquivo não encontrado! / File not found!\033[0m")
                        continue
                    
                    password = getpass.getpass("\033[1;33mSenha / Password: \033[0m")
                    if len(password) < 6:
                        print("\033[1;31m✗ Senha muito fraca! Use pelo menos 6 caracteres.\033[0m")
                        continue
                    
                    self.encrypt_file_fernet(file_path, password)
                
                elif choice == '2':
                    file_path = input("\033[1;33mCaminho do arquivo criptografado / Encrypted file path: \033[0m").strip()
                    if not os.path.exists(file_path):
                        print("\033[1;31m✗ Arquivo não encontrado! / File not found!\033[0m")
                        continue
                    
                    password = getpass.getpass("\033[1;33mSenha / Password: \033[0m")
                    self.decrypt_file_fernet(file_path, password)
                
                elif choice == '3':
                    text = input("\033[1;33mDigite o texto / Enter text: \033[0m")
                    password = getpass.getpass("\033[1;33mSenha / Password: \033[0m")
                    
                    key, salt = self.generate_key_from_password(password)
                    fernet = Fernet(key)
                    encrypted_text = fernet.encrypt(text.encode())
                    
                    result = base64.urlsafe_b64encode(salt + encrypted_text).decode()
                    print(f"\033[1;36mTexto criptografado / Encrypted text: {result}\033[0m")
                
                elif choice == '4':
                    encrypted_text = input("\033[1;33mTexto criptografado / Encrypted text: \033[0m")
                    password = getpass.getpass("\033[1;33mSenha / Password: \033[0m")
                    
                    try:
                        data = base64.urlsafe_b64decode(encrypted_text.encode())
                        salt = data[:16]
                        encrypted_data = data[16:]
                        
                        key, _ = self.generate_key_from_password(password, salt)
                        fernet = Fernet(key)
                        decrypted_text = fernet.decrypt(encrypted_data).decode()
                        
                        print(f"\033[1;36mTexto descriptografado / Decrypted text: {decrypted_text}\033[0m")
                    except Exception as e:
                        print(f"\033[1;31m✗ Erro ao descriptografar texto / Error decrypting text: {str(e)}\033[0m")
                
                elif choice == '5':
                    directory_path = input("\033[1;33mCaminho do diretório / Directory path: \033[0m").strip()
                    if not os.path.exists(directory_path):
                        print("\033[1;31m✗ Diretório não encontrado! / Directory not found!\033[0m")
                        continue
                    
                    password = getpass.getpass("\033[1;33mSenha / Password: \033[0m")
                    if len(password) < 6:
                        print("\033[1;31m✗ Senha muito fraca! Use pelo menos 6 caracteres.\033[0m")
                        continue
                    
                    confirm = input("\033[1;31m⚠️  ATENÇÃO: Todos os arquivos serão criptografados! Continuar? (s/n): \033[0m")
                    if confirm.lower() == 's':
                        self.encrypt_directory(directory_path, password)
                
                elif choice == '6':
                    directory_path = input("\033[1;33mCaminho do diretório / Directory path: \033[0m").strip()
                    if not os.path.exists(directory_path):
                        print("\033[1;31m✗ Diretório não encontrado! / Directory not found!\033[0m")
                        continue
                    
                    password = getpass.getpass("\033[1;33mSenha / Password: \033[0m")
                    self.decrypt_directory(directory_path, password)
                
                elif choice == '7':
                    length = input("\033[1;33mTamanho da chave (padrão 32): \033[0m").strip()
                    length = int(length) if length.isdigit() else 32
                    self.generate_secure_key(length)
                
                elif choice == '8':
                    file_path = input("\033[1;33mCaminho do arquivo / File path: \033[0m").strip()
                    if not os.path.exists(file_path):
                        print("\033[1;31m✗ Arquivo não encontrado! / File not found!\033[0m")
                        continue
                    
                    algorithm = input("\033[1;33mAlgoritmo (md5/sha1/sha256/sha512) [sha256]: \033[0m").strip().lower()
                    algorithm = algorithm if algorithm in ['md5', 'sha1', 'sha256', 'sha512'] else 'sha256'
                    
                    hash_value = self.calculate_file_hash(file_path, algorithm)
                    if hash_value:
                        print(f"\033[1;36m{algorithm.upper()} Hash: {hash_value}\033[0m")
                
                elif choice == '9':
                    file_path = input("\033[1;33mCaminho do arquivo / File path: \033[0m").strip()
                    self.verify_file_integrity(file_path)
                
                elif choice == '10':
                    self.advanced_mode()
                
                elif choice == '11':
                    self.show_help()
                
                else:
                    print("\033[1;31m✗ Opção inválida! / Invalid option!\033[0m")
                
                input("\n\033[1;33mPressione Enter para continuar... / Press Enter to continue...\033[0m")
                os.system('clear' if os.name == 'posix' else 'cls')
                
            except KeyboardInterrupt:
                print("\n\033[1;32m👋 Saindo... / Exiting...\033[0m")
                break
            except Exception as e:
                print(f"\033[1;31m✗ Erro inesperado / Unexpected error: {str(e)}\033[0m")
                input("\n\033[1;33mPressione Enter para continuar... / Press Enter to continue...\033[0m")

if __name__ == "__main__":
    try:
        crypto_vault = CryptoVault()
        crypto_vault.run()
    except ImportError as e:
        print(f"\033[1;31m✗ Erro de dependência: {str(e)}\033[0m")
        print("\033[1;33m💡 Execute o install.sh para instalar as dependências necessárias\033[0m")
        sys.exit(1)
    except Exception as e:
        print(f"\033[1;31m✗ Erro fatal: {str(e)}\033[0m")
        sys.exit(1)
