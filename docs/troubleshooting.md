# Troubleshooting Guide

Common issues and solutions for the Zscaler Bulk URL Uploader.

## Quick Diagnostic Steps

Before diving into specific issues, run these diagnostic steps:

```bash
# 1. Check Python version
python --version
python3 --version

# 2. Verify dependencies
python -c "import jwt, cryptography, requests, yaml; print('✅ All dependencies available')"

# 3. Test configuration
python zscaler_bulk_url_uploader.py --generate-config
python zscaler_bulk_url_uploader.py --config config.yaml --dry-run --csv examples/sample_urls.csv

# 4. Enable verbose logging
python zscaler_bulk_url_uploader.py --verbose --dry-run --csv examples/sample_urls.csv

# 5. Check log file
tail -f zscaler_uploader.log
```

## Authentication Issues

### Issue: Authentication Failed (401)

```
❌ Authentication failed: 401
Response: {"detail": "unauthorized"}
```

**Possible Causes & Solutions:**

#### 1. Incorrect Client ID
```bash
# Verify Client ID in ZIdentity Admin Portal
# Check if client ID in config matches ZIdentity
grep client_id config.yaml
```

#### 2. Certificate Not Uploaded
- Go to ZIdentity Admin Portal → Integration → API Clients
- Verify certificate.pem is uploaded in Authentication section
- Ensure certificate matches your private key

#### 3. Wrong Vanity Domain
```yaml
# Correct format (without .zslogin.net)
vanity_domain: "company"

# Wrong formats
vanity_domain: "company.zslogin.net"  # ❌ Don't include suffix
vanity_domain: "https://company.zslogin.net"  # ❌ Don't include protocol
```

#### 4. Private Key Issues
```bash
# Test private key
openssl rsa -in private_key.pem -check

# Verify certificate and key match
openssl x509 -noout -modulus -in certificate.pem | openssl md5
openssl rsa -noout -modulus -in private_key.pem | openssl md5
# MD5 hashes should be identical
```

### Issue: Private Key Loading Errors

```
❌ Failed to load private key: [Errno 2] No such file or directory: './private_key.pem'
```

**Solutions:**
```bash
# Check file exists
ls -la private_key.pem

# Check permissions
chmod 600 private_key.pem

# Use absolute path
private_key_path: "/full/path/to/private_key.pem"

# Verify file format
file private_key.pem
# Should show: "PEM RSA private key"
```

### Issue: Encrypted Key Password Errors

```
❌ Failed to load private key: Bad decrypt. Incorrect password?
```

**Solutions:**
```bash
# Test password manually
openssl rsa -in private_key.pem -check
# Enter password when prompted

# Check if key is actually encrypted
grep -q "ENCRYPTED" private_key.pem && echo "Key is encrypted" || echo "Key is not encrypted"

# If not encrypted, leave password empty
private_key_password: ""
```

## API Access Issues

### Issue: No Custom URL Categories Found

```
❌ Failed to fetch categories: 401
Response: {"detail": "unauthorized"}
❌ No custom URL categories found!
```

**Root Cause**: API client has no ZIA resource permissions.

**Solutions:**

#### 1. Check ZIdentity Resource Assignment
- Go to ZIdentity Admin Portal → Integration → API Clients
- Click on your API client → Resources tab
- Look for "ZIA [YOUR-ORG] - INTERNAL"
- If missing or no scopes available, contact Zscaler support

#### 2. Verify ZIA API Access
```bash
# Test with curl (replace with your details)
curl -X GET "https://api.zsapi.net/zia/api/v1/urlCategories/lite" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json"
```

#### 3. Check Organization Permissions
- Verify your organization has ZIA API access enabled
- Contact Zscaler support if ZIA resources don't appear in ZIdentity

### Issue: Rate Limiting (429)

```
❌ API request failed: 429 - Rate limit exceeded
```

**Solutions:**
```yaml
# Reduce batch size
upload:
  batch_size: 50    # Smaller batches
  
# Add delays between requests
  retry_attempts: 5
  timeout: 120      # Longer timeout
```

```bash
# Check rate limiting headers
curl -I -X GET "https://api.zsapi.net/zia/api/v1/urlCategories/lite" \
  -H "Authorization: Bearer YOUR_TOKEN"
# Look for X-RateLimit-* headers
```

## CSV Processing Issues

### Issue: CSV File Not Found

```
❌ ConfigurationError: Failed to parse CSV file: [Errno 2] No such file or directory
```

**Solutions:**
```bash
# Check file exists
ls -la your_file.csv

# Use absolute path
python zscaler_bulk_url_uploader.py --csv /full/path/to/file.csv

# Check permissions
chmod 644 your_file.csv
```

### Issue: CSV Encoding Problems

```
❌ UnicodeDecodeError: 'utf-8' codec can't decode byte
```

**Solutions:**
```bash
# Check file encoding
file -bi your_file.csv

# Convert to UTF-8
iconv -f ISO-8859-1 -t UTF-8 your_file.csv > your_file_utf8.csv

# Or specify encoding in config
csv:
  encoding: "latin-1"  # or cp1252, iso-8859-1
```

### Issue: No Valid URLs Found

```
📁 Parsed 0 unique URLs from CSV file
❌ No valid URLs found in CSV file!
```

**Solutions:**
```bash
# Check CSV content
head -10 your_file.csv

# Verify URL format
# Valid: example.com, subdomain.example.com
# Invalid: just-text-no-dots, example
```

### Issue: Too Many Invalid URLs

```
⚠️  Found 50 invalid URLs (skipped)
Invalid URL at row 2, col 1: <script>alert('xss')</script>
```

**Solutions:**
- Clean your CSV data
- Remove non-URL content
- Check for HTML/XML tags
- Validate URLs before uploading

## Network and Connectivity Issues

### Issue: Connection Timeouts

```
❌ Request failed after 3 attempts: ConnectTimeout
```

**Solutions:**
```yaml
# Increase timeout
upload:
  timeout: 120      # Longer timeout
  retry_attempts: 5 # More retries
```

```bash
# Test connectivity
curl -I https://api.zsapi.net/zia/api/v1/

# Check DNS resolution
nslookup api.zsapi.net

# Test from your network
telnet api.zsapi.net 443
```

### Issue: SSL/TLS Errors

```
❌ SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed
```

**Solutions:**
```bash
# Update CA certificates
# Ubuntu/Debian:
sudo apt update && sudo apt install ca-certificates

# CentOS/RHEL:
sudo yum update ca-certificates

# Python certificates
pip install --upgrade certifi
```

### Issue: Proxy Configuration

If you're behind a corporate proxy:

```bash
# Set proxy environment variables
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1

# Or configure in requests
# Add to config.yaml:
proxy:
  http: "http://proxy.company.com:8080"
  https: "http://proxy.company.com:8080"
```

## Installation and Dependency Issues

### Issue: Missing Dependencies

```
❌ Missing required libraries. Please install:
pip install -r requirements.txt
```

**Solutions:**
```bash
# Install dependencies
pip install -r requirements.txt

# If specific package fails
pip install PyJWT cryptography requests PyYAML

# Use virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

### Issue: Cryptography Library Problems

```
❌ ModuleNotFoundError: No module named '_cffi_backend'
```

**Solutions:**
```bash
# Install build dependencies
# Ubuntu/Debian:
sudo apt install build-essential libssl-dev libffi-dev python3-dev

# CentOS/RHEL:
sudo yum install gcc openssl-devel libffi-devel python3-devel

# Reinstall cryptography
pip uninstall cryptography cffi
pip install --no-cache-dir cryptography
```

### Issue: Python Version Compatibility

```
❌ This application requires Python 3.7 or higher
Current version: 3.6.8
```

**Solutions:**
```bash
# Check available Python versions
python3 --version
python3.8 --version
python3.9 --version

# Use specific version
python3.8 zscaler_bulk_url_uploader.py

# Install newer Python (Ubuntu example)
sudo apt install python3.9 python3.9-pip
```

## Configuration Issues

### Issue: Configuration File Not Found

```
❌ Configuration file not found: config.yaml
```

**Solutions:**
```bash
# Generate sample configuration
python zscaler_bulk_url_uploader.py --generate-config

# Use full path
python zscaler_bulk_url_uploader.py --config /full/path/to/config.yaml

# Check current directory
ls -la config.yaml
```

### Issue: Invalid YAML Syntax

```
❌ Error loading configuration: yaml.scanner.ScannerError
```

**Solutions:**
```bash
# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Check indentation (use spaces, not tabs)
# Check for special characters
# Use YAML validator online
```

### Issue: Invalid Configuration Values

```
❌ ValueError: batch_size must be between 1 and 1000
```

**Solutions:**
```yaml
# Check valid ranges
upload:
  batch_size: 100        # 1-1000
  retry_attempts: 3      # 0-10  
  timeout: 60           # 10-300
```

## Performance Issues

### Issue: Slow Upload Speed

**Diagnostic Steps:**
```bash
# Check batch size
grep batch_size config.yaml

# Monitor network usage
# Linux: iotop, nethogs
# Windows: Task Manager → Performance → Network

# Check logs for delays
grep -i "waiting\|timeout\|retry" zscaler_uploader.log
```

**Optimization:**
```yaml
# Increase batch size (if network allows)
upload:
  batch_size: 200

# Reduce timeout for faster failure detection
  timeout: 30

# Disable backups for speed
  backup_existing: false
```

### Issue: Memory Usage Problems

```
❌ MemoryError: Unable to allocate memory
```

**Solutions:**
```bash
# Check available memory
free -h  # Linux
wmic OS get TotalVisibleMemorySize,FreePhysicalMemory  # Windows

# Reduce batch size
batch_size: 50

# Process files in chunks
# Split large CSV files
split -l 10000 large_file.csv chunk_
```

## Debugging Techniques

### Enable Maximum Logging

```yaml
logging:
  level: "DEBUG"
  format: "%(asctime)s [%(levelname)8s] %(name)s:%(lineno)d - %(funcName)s() - %(message)s"
```

### Trace Network Requests

```bash
# Using environment variable
export PYTHONHTTPSVERIFY=0  # Only for debugging SSL issues

# Monitor HTTP traffic
# Linux: tcpdump, wireshark
# macOS: wireshark, Charles Proxy
# Windows: Fiddler, Wireshark
```

### Python Debugging

```python
# Add to script for debugging
import logging
import sys

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('debug.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
```

### Test Individual Components

```bash
# Test authentication only
python -c "
from zscaler_bulk_uploader import ZscalerURLUploader, load_config, setup_logging
config = load_config('config.yaml')
logger = setup_logging(config)
uploader = ZscalerURLUploader(config, logger)
print('Testing authentication...')
result = uploader.authenticate_with_certificate('company', 'client-id', 'private_key.pem')
print(f'Result: {result}')
"

# Test CSV parsing only
python -c "
from zscaler_bulk_uploader import parse_csv_file
import logging
urls = parse_csv_file('test.csv', logging.getLogger())
print(f'Found {len(urls)} URLs: {urls[:5]}')
"
```

## Error Reference

### HTTP Status Codes

- **400 Bad Request**: Invalid request format or parameters
- **401 Unauthorized**: Authentication failed or token expired
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Endpoint or resource not found
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Zscaler API error
- **503 Service Unavailable**: Zscaler service maintenance

### Common Exit Codes

- **0**: Success
- **1**: General error
- **2**: Configuration error
- **3**: Authentication error
- **4**: API error
- **130**: Interrupted by user (Ctrl+C)

## Getting Help

### Before Asking for Help

1. **Check this troubleshooting guide**
2. **Enable debug logging** and check logs
3. **Test with minimal configuration**
4. **Verify network connectivity**
5. **Check Zscaler service status**

### Information to Include

When reporting issues, include:
- Operating system and Python version
- Complete error message and stack trace
- Configuration file (remove sensitive data)
- Log file contents (with debug enabled)
- Steps to reproduce the issue
- CSV file sample (if relevant)

### Support Channels

- 🐛 [GitHub Issues](https://github.com/dunwright/zscaler-bulk-url-uploader/issues)
- 💬 [GitHub Discussions](https://github.com/dunwright/zscaler-bulk-url-uploader/discussions)
- 📧 [Email Support](mailto:dunwright@gmail.com)
- 📚 [Documentation](https://dunwright.github.io/zscaler-bulk-url-uploader/)

### Related Documentation

- 🔐 [Authentication Setup](authentication.md)
- ⚙️ [Configuration Reference](configuration.md)
- 🛠️ [Installation Guide](installation.md)
- 📚 [API Reference](api.md)
