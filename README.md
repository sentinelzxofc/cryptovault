# 🔐 CryptoVault - Advanced Encryption Tool

<div align="center">

![CryptoVault Banner](https://img.shields.io/badge/CryptoVault-v2.1.0-blue?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.7+-green?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Cross--Platform-red?style=for-the-badge)

**🛡️ Military-grade encryption for your files, directories, and sensitive data**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Security](#-security) • [Contributing](#-contributing)

</div>

---

## 🚀 Overview

**CryptoVault** is a powerful, user-friendly encryption tool that provides military-grade security for your files and data. With support for multiple encryption algorithms and an intuitive interface, CryptoVault makes data protection accessible to everyone.

### ✨ Why Choose CryptoVault?

- 🔒 **Military-Grade Security**: AES-256, ChaCha20-Poly1305, and more
- 🎯 **User-Friendly**: Simple CLI interface with clear instructions
- 🌍 **Cross-Platform**: Works on Linux, macOS, Windows, and Termux
- ⚡ **Fast & Efficient**: Optimized for performance
- 🛠️ **Versatile**: Encrypt files, directories, or plain text
- 🔑 **Secure Key Generation**: Built-in cryptographically secure key generator

## 🎯 Features

### 🔐 Encryption Capabilities
- **File Encryption**: Secure individual files with strong encryption
- **Directory Encryption**: Encrypt entire folders recursively
- **Text Encryption**: Encrypt plain text messages
- **Batch Processing**: Handle multiple files simultaneously

### 🛡️ Supported Algorithms
- **Fernet** (Recommended for general use)
- **AES-256-CBC** (Military standard)
- **AES-256-GCM** (Authenticated encryption)
- **ChaCha20-Poly1305** (Modern & fast)
- **Triple DES** (Legacy support)
- **XOR Cipher** (Educational purposes)
- **Caesar Cipher** (Classical cryptography)
- **Vigenère Cipher** (Polyalphabetic cipher)
- **ROT13** (Simple rotation cipher)
- **Base64** (Encoding/Decoding)

### 🔍 Security Features
- **File Integrity Verification**: MD5, SHA1, SHA256, SHA512 hashing
- **Secure Key Derivation**: PBKDF2 with 100,000 iterations
- **Salt Generation**: Cryptographically secure random salts
- **Password Strength Validation**: Enforced minimum security standards

## 📦 Installation

### 🚀 Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/sentinelzxofc/cryptovault.git
cd cryptovault

# Run the installer
chmod +x install.sh
./install.sh
```

### 📱 Manual Installation

#### Prerequisites
- Python 3.7 or higher
- pip3 package manager

#### Install Dependencies
```bash
pip3 install cryptography>=41.0.0 pycryptodome>=3.18.0 colorama>=0.4.6 tqdm>=4.65.0
```

#### Run CryptoVault
```bash
python3 main.py
```

### 🐧 Platform-Specific Instructions

<details>
<summary><b>🐧 Linux (Ubuntu/Debian)</b></summary>

```bash
sudo apt update
sudo apt install python3 python3-pip git
git clone https://github.com/sentinelzxofc/cryptovault.git
cd cryptovault
./install.sh
```
</details>

<details>
<summary><b>🍎 macOS</b></summary>

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python and Git
brew install python3 git

# Clone and install CryptoVault
git clone https://github.com/sentinelzxofc/cryptovault.git
cd cryptovault
./install.sh
```
</details>

<details>
<summary><b>📱 Termux (Android)</b></summary>

```bash
pkg update && pkg upgrade
pkg install python git
git clone https://github.com/sentinelzxofc/cryptovault.git
cd cryptovault
./install.sh
```
</details>

## 🎮 Usage

### 🚀 Quick Start

After installation, simply run:
```bash
cryptovault
```

Or directly:
```bash
python3 main.py
```

### 📋 Main Menu Options

```
┌─────────────────────────────────────────────────────────────────┐
│                        MENU PRINCIPAL                          │
├─────────────────────────────────────────────────────────────────┤
│ [1] Encrypt File                                               │
│ [2] Decrypt File                                               │
│ [3] Encrypt Text                                               │
│ [4] Decrypt Text                                               │
│ [5] Encrypt Directory                                          │
│ [6] Decrypt Directory                                          │
│ [7] Generate Secure Key                                        │
│ [8] File Hash                                                  │
│ [9] Verify Integrity                                           │
│ [10] Advanced Mode                                             │
│ [11] Help                                                      │
│ [0] Exit                                                       │
└─────────────────────────────────────────────────────────────────┘
```

### 💡 Usage Examples

#### 🔒 Encrypt a File
```bash
# Select option 1 from the menu
# Enter file path: /path/to/your/file.txt
# Enter password: [your-strong-password]
# File will be encrypted as: file.txt.cryptovault
```

#### 🔓 Decrypt a File
```bash
# Select option 2 from the menu
# Enter encrypted file path: /path/to/file.txt.cryptovault
# Enter password: [your-password]
# Original file will be restored
```

#### 📁 Encrypt Directory
```bash
# Select option 5 from the menu
# Enter directory path: /path/to/directory
# Enter password: [your-strong-password]
# All files in directory will be encrypted
```

## 🛡️ Security

### 🔐 Encryption Standards

CryptoVault implements industry-standard encryption algorithms:

- **AES-256**: Advanced Encryption Standard with 256-bit keys
- **ChaCha20-Poly1305**: Modern authenticated encryption
- **PBKDF2**: Password-Based Key Derivation Function 2
- **Secure Random**: Cryptographically secure random number generation

### 🔑 Password Security

- **Minimum Length**: 6 characters (12+ recommended)
- **Complexity**: Use uppercase, lowercase, numbers, and symbols
- **Uniqueness**: Never reuse passwords
- **Storage**: Store passwords securely (password manager recommended)

### ⚠️ Important Security Notice

> **🚨 CRITICAL WARNING**: If you forget your password, your data cannot be recovered. There is no backdoor or password reset function. Always:
> - Use strong, memorable passwords
> - Keep secure backups of important data
> - Store passwords in a secure password manager

## 🎨 Screenshots

### Main Interface
```
██████╗ ██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
██╔══██╗██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
██████╔╝██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██║   ██║███████║██║   ██║██║     ██║   
██╔══██╗██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   
██████╔╝██║  ██║   ██║   ██║        ██║   ╚██████╔╝ ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   
╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝   ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   
                    Advanced Encryption Tool v2.1.0
```

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### 🐛 Bug Reports
- Use the [Issues](https://github.com/sentinelzxofc/cryptovault/issues) tab
- Provide detailed reproduction steps
- Include system information and error messages

### 💡 Feature Requests
- Check existing [Issues](https://github.com/sentinelzxofc/cryptovault/issues) first
- Describe the feature and its benefits
- Consider implementation complexity

### 🔧 Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### 📝 Development Setup
```bash
git clone https://github.com/sentinelzxofc/cryptovault.git
cd cryptovault
pip3 install -r requirements.txt
python3 main.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Cryptography Community**: For providing robust encryption libraries
- **Python Foundation**: For the excellent Python programming language
- **Contributors**: Everyone who has contributed to making CryptoVault better

## 📞 Support

### 🆘 Getting Help
- 📖 Read the [Documentation](https://github.com/sentinelzxofc/cryptovault/wiki)
- 🐛 Report [Issues](https://github.com/sentinelzxofc/cryptovault/issues)
- 💬 Join our [Discussions](https://github.com/sentinelzxofc/cryptovault/discussions)

### 📧 Contact
- **Author**: sentinelzxofc
- **Repository**: [github.com/sentinelzxofc/cryptovault](https://github.com/sentinelzxofc/cryptovault)

---

<div align="center">

**⭐ If you find CryptoVault useful, please give it a star! ⭐**

![GitHub stars](https://img.shields.io/github/stars/sentinelzxofc/cryptovault?style=social)
![GitHub forks](https://img.shields.io/github/forks/sentinelzxofc/cryptovault?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/sentinelzxofc/cryptovault?style=social)

**Made with ❤️ by [sentinelzxofc](https://github.com/sentinelzxofc)**

</div>
