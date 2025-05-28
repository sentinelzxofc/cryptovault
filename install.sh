#!/bin/bash

clear

echo -e "\033[1;36m"
echo "██████╗ ██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗"
echo "██╔══██╗██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝"
echo "██████╔╝██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██║   ██║███████║██║   ██║██║     ██║   "
echo "██╔══██╗██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   "
echo "██████╔╝██║  ██║   ██║   ██║        ██║   ╚██████╔╝ ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   "
echo "╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝   ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   "
echo -e "\033[1;33m"
echo "                    Advanced Encryption Tool - Installer"
echo "                    Author: sentinelzxofc"
echo "                    Repository: https://github.com/sentinelzxofc/cryptovault"
echo -e "\033[1;36m"
echo "========================================================================"
echo -e "\033[0m"

echo -e "\033[1;32m[INFO]\033[0m Starting CryptoVault installation..."
echo

check_command() {
    command -v "$1" &> /dev/null && echo -e "\033[1;32m[✓]\033[0m $1 is already installed" && return 0
    echo -e "\033[1;31m[✗]\033[0m $1 is not installed" && return 1
}

install_package() {
    echo -e "\033[1;33m[INSTALL]\033[0m Installing $1..."
    eval "$2" && echo -e "\033[1;32m[✓]\033[0m $1 installed successfully" || { echo -e "\033[1;31m[✗]\033[0m Failed to install $1"; return 1; }
}

install_rust() {
    if ! command -v rustc &> /dev/null; then
        echo -e "\033[1;33m[INSTALL]\033[0m Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source $HOME/.cargo/env
        rustc --version && echo -e "\033[1;32m[✓]\033[0m Rust installed successfully" || { echo -e "\033[1;31m[✗]\033[0m Failed to install Rust"; return 1; }
    else
        echo -e "\033[1;32m[✓]\033[0m Rust is already installed"
    fi
}

detect_system() {
    if [[ "$OSTYPE" == "linux-android"* ]] || [[ -d "/data/data/com.termux" ]]; then
        echo "termux"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt &> /dev/null; then
            echo "debian"
        elif command -v yum &> /dev/null; then
            echo "redhat"
        elif command -v pacman &> /dev/null; then
            echo "arch"
        elif command -v apk &> /dev/null; then
            echo "alpine"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

SYSTEM=$(detect_system)
echo -e "\033[1;34m[SYSTEM]\033[0m Detected system: $SYSTEM"
echo

echo -e "\033[1;33m[CHECK]\033[0m Checking system requirements..."

case $SYSTEM in
    "termux")
        pkg update -y && pkg upgrade -y
        install_package "build tools" "pkg install python-dev clang make libffi-dev openssl-dev -y"
        ;;
    "debian")
        sudo apt update && sudo apt upgrade -y
        install_package "build tools" "sudo apt install build-essential libssl-dev libffi-dev python3-dev -y"
        ;;
    "redhat")
        sudo yum update -y
        install_package "build tools" "sudo yum groupinstall 'Development Tools' -y && sudo yum install openssl-devel libffi-devel python3-devel -y"
        ;;
    "arch")
        sudo pacman -Syu --noconfirm
        install_package "build tools" "sudo pacman -S base-devel openssl libffi python3 --noconfirm"
        ;;
    "alpine")
        apk update && apk upgrade
        install_package "build tools" "apk add build-base openssl-dev libffi-dev python3-dev"
        ;;
    "macos")
        if ! command -v brew &> /dev/null; then
            echo -e "\033[1;31m[ERROR]\033[0m Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        install_package "build tools" "brew install openssl libffi python3"
        ;;
    *)
        echo -e "\033[1;31m[ERROR]\033[0m Unsupported system. Please install dependencies manually."
        exit 1
        ;;
esac

if ! check_command python3; then
    case $SYSTEM in
        "termux")
            install_package "Python3" "pkg install python -y"
            ;;
        "debian")
            install_package "Python3" "sudo apt install python3 python3-pip -y"
            ;;
        "redhat")
            install_package "Python3" "sudo yum install python3 python3-pip -y"
            ;;
        "arch")
            install_package "Python3" "sudo pacman -S python python-pip --noconfirm"
            ;;
        "alpine")
            install_package "Python3" "apk add python3 py3-pip"
            ;;
        "macos")
            install_package "Python3" "brew install python3"
            ;;
        *)
            echo -e "\033[1;31m[ERROR]\033[0m Unsupported system. Please install Python3 manually."
            exit 1
            ;;
    esac
fi

if ! check_command pip3; then
    case $SYSTEM in
        "termux")
            install_package "pip3" "pkg install python -y"
            ;;
        "debian")
            install_package "pip3" "sudo apt install python3-pip -y"
            ;;
        "redhat")
            install_package "pip3" "sudo yum install python3-pip -y"
            ;;
        "arch")
            install_package "pip3" "sudo pacman -S python-pip --noconfirm"
            ;;
        "alpine")
            install_package "pip3" "apk add py3-pip"
            ;;
        "macos")
            echo -e "\033[1;32m[INFO]\033[0m pip3 should be included with Python3"
            ;;
    esac
fi

install_rust

echo
echo -e "\033[1;33m[INSTALL]\033[0m Creating requirements.txt..."
cat > requirements.txt << EOL
cryptography>=41.0.0
pycryptodome>=3.18.0
colorama>=0.4.6
tqdm>=4.65.0
EOL

echo -e "\033[1;33m[INSTALL]\033[0m Installing Python dependencies from requirements.txt..."

if ! pip3 install -r requirements.txt --user; then
    echo -e "\033[1;33m[RETRY]\033[0m Trying alternative installation method..."
    python3 -m pip install -r requirements.txt --user --no-build-isolation || {
        echo -e "\033[1;31m[ERROR]\033[0m Failed to install dependencies"
        exit 1
    }
fi

echo
echo -e "\033[1;33m[SETUP]\033[0m Setting up CryptoVault..."

if [[ ! -f "main.py" ]]; then
    echo -e "\033[1;31m[ERROR]\033[0m main.py not found in current directory"
    exit 1
fi

chmod +x main.py

if [[ "$SYSTEM" == "termux" ]]; then
    INSTALL_DIR="$HOME/cryptovault"
else
    INSTALL_DIR="$HOME/.local/bin/cryptovault"
fi

echo -e "\033[1;34m[INSTALL]\033[0m Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

echo -e "\033[1;34m[COPY]\033[0m Copying files to installation directory..."
cp main.py "$INSTALL_DIR/"
cp install.sh "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"

if [[ -f "README.md" ]]; then
    cp README.md "$INSTALL_DIR/"
fi

echo -e "\033[1;34m[ALIAS]\033[0m Creating command alias..."

SHELL_RC=""
if [[ "$SHELL" == *"zsh"* ]]; then
    SHELL_RC="$HOME/.zshrc"
elif [[ "$SHELL" == *"bash"* ]]; then
    if [[ "$SYSTEM" == "termux" ]]; then
        SHELL_RC="$HOME/.bashrc"
    else
        SHELL_RC="$HOME/.bash_profile"
    fi
else
    SHELL_RC="$HOME/.bashrc"
fi

ALIAS_LINE="alias cryptovault='python3 $INSTALL_DIR/main.py'"

if ! grep -q "alias cryptovault=" "$SHELL_RC" 2>/dev/null; then
    echo "" >> "$SHELL_RC"
    echo "# CryptoVault alias" >> "$SHELL_RC"
    echo "$ALIAS_LINE" >> "$SHELL_RC"
    echo -e "\033[1;32m[✓]\033[0m Alias added to $SHELL_RC"
else
    echo -e "\033[1;33m[INFO]\033[0m Alias already exists in $SHELL_RC"
fi

echo
echo -e "\033[1;32m[SUCCESS]\033[0m CryptoVault installation completed successfully!"
echo
echo -e "\033[1;36m" + "="*70
echo "                        INSTALLATION COMPLETE"
echo "="*70 + "\033[0m"
echo
echo -e "\033[1;33mHow to use CryptoVault:\033[0m"
echo
echo -e "\033[1;32m1. Restart your terminal or run:\033[0m"
echo -e "   \033[1;36msource $SHELL_RC\033[0m"
echo
echo -e "\033[1;32m2. Run CryptoVault with:\033[0m"
echo -e "   \033[1;36mcryptovault\033[0m"
echo
echo -e "\033[1;32m3. Or run directly:\033[0m"
echo -e "   \033[1;36mpython3 $INSTALL_DIR/main.py\033[0m"
echo
echo -e "\033[1;33mFeatures:\033[0m"
echo -e "• \033[1;36mFile & Directory Encryption\033[0m"
echo -e "• \033[1;36mMultiple Encryption Algorithms\033[0m"
echo -e "• \033[1;36mSecure Key Generation\033[0m"
echo -e "• \033[1;36mFile Integrity Verification\033[0m"
echo -e "• \033[1;36mAdvanced Cryptographic Modes\033[0m"
echo
echo -e "\033[1;31mIMPORTANT SECURITY NOTICE:\033[0m"
echo -e "• Always use strong passwords (12+ characters)"
echo -e "• Keep your passwords safe - lost passwords = lost data"
echo -e "• Make backups before encryption"
echo
echo -e "\033[1;32mRepository:\033[0m \033[1;36mhttps://github.com/sentinelzxofc/cryptovault\033[0m"
echo -e "\033[1;32mAuthor:\033[0m \033[1;36msentinelzxofc\033[0m"
echo
echo -e "\033[1;33mThank you for using CryptoVault! 🔐\033[0m"
echo