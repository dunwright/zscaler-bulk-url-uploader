# Zscaler Bulk URL Uploader

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A professional tool for bulk uploading URLs to Zscaler Internet Access (ZIA) custom URL categories with secure certificate-based authentication.

## ✨ Features

- 🔐 **Secure Authentication** - Certificate-based authentication (recommended) or client secret
- 📁 **Flexible CSV Parsing** - Supports any CSV format, auto-detects headers and delimiters
- 🔍 **Duplicate Detection** - Identifies and handles duplicate URLs intelligently  
- 📊 **Batch Processing** - Handles large URL lists with configurable batch sizes
- 🔄 **Robust Error Handling** - Automatic retries, exponential backoff, and detailed logging
- ⚙️ **Configuration Files** - YAML-based configuration for easy automation
- 📝 **Comprehensive Logging** - Detailed logs for troubleshooting and audit trails
- 🧪 **Dry Run Mode** - Validate inputs without making changes
- 🔧 **CLI Interface** - Command-line interface for automation and scripting

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/zscaler-bulk-url-uploader.git
cd zscaler-bulk-url-uploader

# Install dependencies
pip install -r requirements.txt

# Generate sample configuration
python zscaler_bulk_uploader.py --generate-config

# Get authentication help
python zscaler_bulk_uploader.py --help-auth
```

### Basic Usage

```bash
# Interactive mode
python zscaler_bulk_uploader.py --csv urls.csv

# Using configuration file
python zscaler_bulk_uploader.py --csv urls.csv --config config.yaml

# Dry run (validate without uploading)
python zscaler_bulk_uploader.py --csv urls.csv --dry-run
```

## 📋 Prerequisites

### System Requirements
- **Python 3.7+** (Python 3.11+ recommended)
- **Operating System**: Linux, macOS, Windows, WSL
- **Network**: HTTPS access to Zscaler API endpoints

### Zscaler Requirements
- **ZIA Subscription** with API access enabled
- **ZIdentity Admin Portal** access
- **Custom URL Categories** created in ZIA
- **API Client** configured in ZIdentity

## 🔐 Authentication Setup

### Certificate-Based Authentication (Recommended)

1. **Generate Private Key and Certificate:**
   ```bash
   # Generate private key
   openssl genrsa -out private_key.pem 2048
   
   # Generate self-signed certificate
   openssl req -new -x509 -key private_key.pem -out certificate.pem -days 365
   ```

2. **Configure ZIdentity:**
   - Go to ZIdentity Admin Portal
   - Navigate to Integration > API Clients
   - Create or edit your API client
   - Upload `certificate.pem` in the Authentication section
   - Assign appropriate ZIA API scopes/resources

3. **Configure Application:**
   ```yaml
   # config.yaml
   zscaler:
     vanity_domain: "your-company"
     client_id: "your-client-id"
     private_key_path: "./private_key.pem"
   ```

### Client Secret Authentication (Alternative)

```yaml
# config.yaml
zscaler:
  vanity_domain: "your-company" 
  client_id: "your-client-id"
  client_secret: "your-client-secret"
```

## 📁 CSV File Format

The tool accepts any CSV format and automatically:
- Detects headers and delimiters
- Finds URLs in any column
- Removes `http://` and `https://` prefixes
- Validates URL format
- Removes duplicates

### Example CSV Formats

**Simple list:**
```csv
URL
example.com
https://test.com
subdomain.example.org
```

**Multiple columns:**
```csv
Name,URL,Category
Example Site,https://example.com,Business
Test Site,test.com,Development
```

**No headers:**
```csv
example.com
test.com
subdomain.example.org
```

## ⚙️ Configuration

### Sample Configuration File

```yaml
# config.yaml
zscaler:
  vanity_domain: "your-company"
  client_id: "your-client-id"
  private_key_path: "./private_key.pem"
  private_key_password: ""  # Optional, if key is encrypted

upload:
  batch_size: 100           # URLs per batch
  retry_attempts: 3         # Number of retries
  timeout: 60              # Request timeout (seconds)
  backup_existing: true    # Backup existing URLs

logging:
  level: "INFO"            # DEBUG, INFO, WARNING, ERROR
  file: "zscaler_uploader.log"
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
```

### Environment Variables

You can also use environment variables:

```bash
export ZSCALER_VANITY_DOMAIN="your-company"
export ZSCALER_CLIENT_ID="your-client-id"
export ZSCALER_PRIVATE_KEY_PATH="./private_key.pem"
```

## 🔧 Command Line Options

```bash
python zscaler_bulk_uploader.py [OPTIONS]

Options:
  --csv PATH              CSV file containing URLs to upload
  --config PATH           Configuration file path
  --category NAME         Target URL category name or ID  
  --dry-run              Validate inputs without uploading
  --generate-config      Generate sample configuration file
  --help-auth            Show authentication setup help
  --verbose, -v          Enable verbose logging
  --version              Show version information
  --help                 Show help message
```

## 📊 Usage Examples

### Basic Upload
```bash
python zscaler_bulk_uploader.py --csv my_urls.csv
```

### With Custom Configuration
```bash
python zscaler_bulk_uploader.py \
  --csv urls.csv \
  --config /path/to/config.yaml \
  --verbose
```

### Validation Only
```bash
python zscaler_bulk_uploader.py --csv urls.csv --dry-run
```

### Automated Script
```bash
#!/bin/bash
python zscaler_bulk_uploader.py \
  --csv daily_urls.csv \
  --config production.yaml \
  --category "Daily Blocked Sites" \
  >> upload.log 2>&1
```

## 🔍 Troubleshooting

### Common Issues

**Authentication Failed (401)**
- Check API client configuration in ZIdentity
- Verify certificate is uploaded correctly
- Ensure API scopes/resources are assigned

**No Categories Found**
- Verify ZIA API resources are assigned to your API client
- Check if custom URL categories exist in ZIA
- Confirm API client has appropriate permissions

**Certificate Loading Errors**
- Verify private key file path and permissions
- Check if private key requires a password
- Ensure cryptography library is properly installed

**CSV Parsing Issues**
- Check file encoding (should be UTF-8)
- Verify CSV format and structure
- Look for invalid characters in URLs

### Debugging

Enable debug logging:
```bash
python zscaler_bulk_uploader.py --csv urls.csv --verbose
```

Check log file:
```bash
tail -f zscaler_uploader.log
```

## 🧪 Testing

```bash
# Run tests
pytest tests/

# Run with coverage
pytest --cov=zscaler_bulk_uploader tests/

# Run specific test
pytest tests/test_authentication.py
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements.txt

# Install pre-commit hooks
pre-commit install

# Run code formatting
black zscaler_bulk_uploader.py

# Run linting
flake8 zscaler_bulk_uploader.py

# Run type checking
mypy zscaler_bulk_uploader.py
```

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Authentication Setup](docs/authentication.md)
- [Configuration Reference](docs/configuration.md)
- [API Reference](docs/api.md)
- [Troubleshooting Guide](docs/troubleshooting.md)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Zscaler](https://www.zscaler.com/) for the ZIA API
- [PyJWT](https://github.com/jpadilla/pyjwt) for JWT handling
- [Cryptography](https://github.com/pyca/cryptography) for certificate support
- [Requests](https://github.com/psf/requests) for HTTP client

## 📞 Support

- 🐛 [Report Bugs](https://github.com/dunwright/zscaler-bulk-url-uploader/issues)
- 💡 [Request Features](https://github.com/dunwright/zscaler-bulk-url-uploader/issues)
- 📖 [Read Documentation](https://dunwright.github.io/zscaler-bulk-url-uploader/)
- 💬 [Discussions](https://github.com/dunwright/zscaler-bulk-url-uploader/discussions)

---

⭐ If this tool helps you, please give it a star on GitHub!
