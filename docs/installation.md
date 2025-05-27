# Installation Guide

This guide covers installation of the Zscaler Bulk URL Uploader on various platforms.

## System Requirements

### Minimum Requirements
- **Python**: 3.7 or higher (Python 3.11+ recommended)
- **Memory**: 512MB RAM
- **Disk Space**: 100MB free space
- **Network**: HTTPS access to Zscaler API endpoints

### Supported Platforms
- **Linux**: Ubuntu 18.04+, CentOS 7+, RHEL 7+, Debian 9+
- **Windows**: Windows 10, Windows Server 2016+
- **macOS**: macOS 10.14+
- **WSL**: Windows Subsystem for Linux (Ubuntu 20.04+)

## Quick Installation

### Option 1: Direct Download
```bash
# Clone the repository
git clone https://github.com/dunwright/zscaler-bulk-url-uploader.git
cd zscaler-bulk-url-uploader

# Install dependencies
pip install -r requirements.txt

# Verify installation
python zscaler_bulk_url_uploader.py --version
```

### Option 2: PyPI Installation (when published)
```bash
# Install from PyPI
pip install zscaler-bulk-url-uploader

# Run the tool
zscaler-uploader --help
```

## Platform-Specific Installation

### Ubuntu/Debian
```bash
# Update system packages
sudo apt update && sudo apt upgrade

# Install Python and pip
sudo apt install python3 python3-pip python3-venv

# Install build dependencies
sudo apt install build-essential libssl-dev libffi-dev python3-dev

# Clone and install
git clone https://github.com/dunwright/zscaler-bulk-url-uploader.git
cd zscaler-bulk-url-uploader
pip3 install -r requirements.txt
```

### CentOS/RHEL
```bash
# Install Python and development tools
sudo yum install python3 python3-pip python3-devel
sudo yum groupinstall "Development Tools"
sudo yum install openssl-devel libffi-devel

# Clone and install
git clone https://github.com/dunwright/zscaler-bulk-url-uploader.git
cd zscaler-bulk-url-uploader
pip3 install -r requirements.txt
```

### Windows
```powershell
# Install Python from python.org or Microsoft Store
# Download and install Git from git-scm.com

# Clone repository
git clone https://github.com/dunwright/zscaler-bulk-url-uploader.git
cd zscaler-bulk-url-uploader

# Install dependencies
pip install -r requirements.txt
```

### macOS
```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python and dependencies
brew install python3 openssl libffi

# Clone and install
git clone https://github.com/dunwright/zscaler-bulk-url-uploader.git
cd zscaler-bulk-url-uploader
pip3 install -r requirements.txt
```

### Windows Subsystem for Linux (WSL)
```bash
# Follow Ubuntu installation steps in WSL terminal
# See main README for detailed WSL setup instructions

# Enable virtualization features if needed
# From PowerShell as Administrator:
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```

## Virtual Environment Installation (Recommended)

Using virtual environments isolates dependencies and prevents conflicts:

```bash
# Create virtual environment
python3 -m venv zscaler-env

# Activate virtual environment
# Linux/macOS:
source zscaler-env/bin/activate
# Windows:
zscaler-env\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
python zscaler_bulk_url_uploader.py --version

# Deactivate when done
deactivate
```

## Docker Installation

### Using Pre-built Image (when available)
```bash
# Pull image
docker pull dunwright/zscaler-bulk-uploader:latest

# Run container
docker run -v $(pwd)/config:/app/config \
           -v $(pwd)/data:/app/data \
           dunwright/zscaler-bulk-uploader:latest --help
```

### Building from Source
```bash
# Clone repository
git clone https://github.com/dunwright/zscaler-bulk-url-uploader.git
cd zscaler-bulk-url-uploader

# Build Docker image
docker build -t zscaler-uploader .

# Run container
docker run -v $(pwd)/config:/app/config \
           -v $(pwd)/data:/app/data \
           zscaler-uploader --help
```

## Development Installation

For contributors and developers:

```bash
# Clone repository
git clone https://github.com/dunwright/zscaler-bulk-url-uploader.git
cd zscaler-bulk-url-uploader

# Create virtual environment
python3 -m venv dev-env
source dev-env/bin/activate  # Linux/macOS
# dev-env\Scripts\activate   # Windows

# Install in development mode
pip install -e .

# Install development dependencies
pip install -r requirements.txt

# Install pre-commit hooks
pre-commit install

# Run tests
pytest tests/
```

## Verification

After installation, verify everything works:

```bash
# Check version
python zscaler_bulk_url_uploader.py --version

# Test import
python -c "import zscaler_bulk_uploader; print('Import successful')"

# Check dependencies
python -c "import jwt, cryptography, requests, yaml; print('All dependencies available')"

# Generate sample config
python zscaler_bulk_url_uploader.py --generate-config

# Get help
python zscaler_bulk_url_uploader.py --help
```

## Common Installation Issues

### SSL Certificate Errors
```bash
# Update certificates
# Ubuntu/Debian:
sudo apt update && sudo apt install ca-certificates

# CentOS/RHEL:
sudo yum update ca-certificates
```

### Python Version Issues
```bash
# Check Python version
python --version
python3 --version

# Use specific Python version
python3.11 -m pip install -r requirements.txt
```

### Permission Errors
```bash
# Install in user directory
pip install --user -r requirements.txt

# Or use virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Windows-Specific Issues
```powershell
# If pip is not recognized
python -m pip install -r requirements.txt

# If execution policy prevents scripts
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Cryptography Library Issues
```bash
# Install build dependencies first
# Ubuntu/Debian:
sudo apt install build-essential libssl-dev libffi-dev python3-dev

# CentOS/RHEL:
sudo yum install gcc openssl-devel libffi-devel python3-devel

# Then reinstall cryptography
pip uninstall cryptography
pip install cryptography
```

## Uninstallation

### Standard Installation
```bash
# Remove virtual environment
rm -rf zscaler-env/

# Remove cloned repository
rm -rf zscaler-bulk-url-uploader/
```

### PyPI Installation
```bash
pip uninstall zscaler-bulk-url-uploader
```

### Docker
```bash
# Remove container
docker rm zscaler-uploader

# Remove image
docker rmi dunwright/zscaler-bulk-uploader
```

## Next Steps

After installation:
1. **Configure Authentication** - See [Authentication Guide](authentication.md)
2. **Set up Configuration** - See [Configuration Reference](configuration.md)
3. **Run Your First Upload** - See main [README](../README.md)

## Getting Help

- 🐛 [Report Installation Issues](https://github.com/dunwright/zscaler-bulk-url-uploader/issues)
- 💬 [Ask Questions](https://github.com/dunwright/zscaler-bulk-url-uploader/discussions)
- 📖 [Read Documentation](https://dunwright.github.io/zscaler-bulk-url-uploader/)
