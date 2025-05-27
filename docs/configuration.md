# Configuration Reference

Complete reference for configuring the Zscaler Bulk URL Uploader.

## Configuration Methods

The application supports multiple configuration methods in order of precedence:

1. **Command-line arguments** (highest priority)
2. **Environment variables**
3. **Configuration files** (YAML)
4. **Default values** (lowest priority)

## Configuration Files

### File Locations (in order of precedence)

1. **Specified via --config**: `--config /path/to/config.yaml`
2. **Current directory**: `./config.yaml` or `./config.yml`
3. **User home directory**: `~/.zscaler/config.yaml`
4. **System-wide**: `/etc/zscaler/config.yaml` (Linux/macOS)

### Sample Configuration

```yaml
# Complete configuration example
zscaler:
  # Required: Your Zscaler vanity domain (without .zslogin.net)
  vanity_domain: "your-company"
  
  # Required: OAuth Client ID from ZIdentity Admin Portal  
  client_id: "12345678-abcd-1234-efgh-123456789012"
  
  # Certificate Authentication (Recommended)
  private_key_path: "./private_key.pem"
  private_key_password: ""  # Leave empty if key is not encrypted
  
  # Alternative: Client Secret Authentication (Less Secure)
  # client_secret: "your-client-secret-here"
  
  # API Configuration (usually no need to change)
  base_url: "https://api.zsapi.net/zia/api/v1"
  token_url_template: "https://{vanity_domain}.zslogin.net/oauth2/v1/token"
  audience: "https://api.zscaler.com"

upload:
  # Maximum URLs per batch request (1-1000, recommended: 100)
  batch_size: 100
  
  # Number of retry attempts for failed requests (0-10)
  retry_attempts: 3
  
  # Request timeout in seconds (10-300)
  timeout: 60
  
  # Create backup of existing URLs before upload
  backup_existing: true

logging:
  # Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
  level: "INFO"
  
  # Log file path (relative or absolute)
  file: "zscaler_uploader.log"
  
  # Log message format (Python logging format)
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  
  # Maximum log file size in MB (0 = no rotation)
  max_file_size: 10
  
  # Number of backup log files to keep
  backup_count: 5

# Optional: Default values for common operations
defaults:
  # Default CSV file path
  csv_file: ""
  
  # Default target category (name or ID)
  target_category: ""
  
  # Automatically remove duplicates without confirmation
  auto_remove_duplicates: false
  
  # Default to dry-run mode for safety
  dry_run: false

# Optional: Custom CSV parsing settings
csv:
  # Expected encoding (utf-8, latin-1, cp1252, etc.)
  encoding: "utf-8"
  
  # CSV delimiter (auto-detect if empty)
  delimiter: ""
  
  # Whether CSV has headers
  has_headers: null  # null = auto-detect, true/false = force
  
  # Skip empty rows
  skip_empty_rows: true
  
  # Maximum number of URLs to process (0 = unlimited)
  max_urls: 0
```

## Environment Variables

All configuration options can be set via environment variables using the prefix `ZSCALER_`:

```bash
# Authentication
export ZSCALER_VANITY_DOMAIN="your-company"
export ZSCALER_CLIENT_ID="your-client-id"
export ZSCALER_PRIVATE_KEY_PATH="./private_key.pem"
export ZSCALER_PRIVATE_KEY_PASSWORD=""
export ZSCALER_CLIENT_SECRET="your-client-secret"

# Upload settings
export ZSCALER_BATCH_SIZE="100"
export ZSCALER_RETRY_ATTEMPTS="3"
export ZSCALER_TIMEOUT="60"
export ZSCALER_BACKUP_EXISTING="true"

# Logging
export ZSCALER_LOG_LEVEL="INFO"
export ZSCALER_LOG_FILE="zscaler_uploader.log"

# Defaults
export ZSCALER_CSV_FILE="./urls.csv"
export ZSCALER_TARGET_CATEGORY="My Category"
export ZSCALER_DRY_RUN="false"
```

## Command-Line Arguments

```bash
# Core options
python zscaler_bulk_url_uploader.py \
  --config /path/to/config.yaml \     # Configuration file
  --csv /path/to/urls.csv \           # CSV file with URLs  
  --category "Category Name" \        # Target category
  --dry-run \                         # Validate only, don't upload
  --verbose                           # Enable debug logging

# Utility options
python zscaler_bulk_url_uploader.py \
  --generate-config \                 # Create sample config file
  --help-auth \                       # Show authentication help
  --version                           # Show version info
```

## Detailed Configuration Options

### Zscaler Section

#### `vanity_domain` (Required)
Your organization's Zscaler vanity domain **without** the `.zslogin.net` suffix.

```yaml
vanity_domain: "acme-corp"  # For acme-corp.zslogin.net
```

**Environment**: `ZSCALER_VANITY_DOMAIN`

#### `client_id` (Required)
OAuth Client ID from ZIdentity Admin Portal.

```yaml
client_id: "12345678-abcd-1234-efgh-123456789012"
```

**Environment**: `ZSCALER_CLIENT_ID`

#### `private_key_path` (Certificate Auth)
Path to private key file for certificate-based authentication.

```yaml
private_key_path: "./keys/private_key.pem"     # Relative path
private_key_path: "/etc/ssl/private/key.pem"   # Absolute path  
private_key_path: "~/zscaler/private_key.pem"  # Home directory
```

**Environment**: `ZSCALER_PRIVATE_KEY_PATH`

#### `private_key_password` (Optional)
Password for encrypted private key files.

```yaml
private_key_password: "my-secure-password"
private_key_password: ""  # Empty for unencrypted keys
```

**Environment**: `ZSCALER_PRIVATE_KEY_PASSWORD`

#### `client_secret` (Secret Auth)
Client secret for secret-based authentication.

```yaml
client_secret: "abcdef123456789"
```

**Environment**: `ZSCALER_CLIENT_SECRET`

⚠️ **Security Warning**: Avoid storing secrets in configuration files. Use environment variables or secure vaults.

### Upload Section

#### `batch_size`
Number of URLs to include in each API request.

```yaml
batch_size: 100    # Recommended for most cases
batch_size: 50     # For slower connections
batch_size: 200    # For high-speed connections
```

**Range**: 1-1000  
**Default**: 100  
**Environment**: `ZSCALER_BATCH_SIZE`

#### `retry_attempts`
Number of times to retry failed API requests.

```yaml
retry_attempts: 3   # Default
retry_attempts: 0   # No retries
retry_attempts: 5   # More aggressive retrying
```

**Range**: 0-10  
**Default**: 3  
**Environment**: `ZSCALER_RETRY_ATTEMPTS`

#### `timeout`
Request timeout in seconds.

```yaml
timeout: 60    # Default
timeout: 30    # Faster timeout
timeout: 120   # Longer timeout for slow connections
```

**Range**: 10-300  
**Default**: 60  
**Environment**: `ZSCALER_TIMEOUT`

#### `backup_existing`
Whether to create backups of existing URL lists before modification.

```yaml
backup_existing: true   # Create backups (recommended)
backup_existing: false  # No backups
```

**Default**: true  
**Environment**: `ZSCALER_BACKUP_EXISTING`

### Logging Section

#### `level`
Logging verbosity level.

```yaml
level: "DEBUG"     # Maximum detail
level: "INFO"      # Default level
level: "WARNING"   # Only warnings and errors
level: "ERROR"     # Only errors
level: "CRITICAL"  # Only critical errors
```

**Default**: "INFO"  
**Environment**: `ZSCALER_LOG_LEVEL`

#### `file`
Log file path.

```yaml
file: "zscaler_uploader.log"           # Current directory
file: "/var/log/zscaler/uploader.log"  # System log directory
file: "~/logs/zscaler.log"             # User log directory
```

**Default**: "zscaler_uploader.log"  
**Environment**: `ZSCALER_LOG_FILE`

#### `format`
Log message format using Python logging format.

```yaml
# Default format
format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Simplified format
format: "%(levelname)s: %(message)s"

# Detailed format
format: "%(asctime)s [%(levelname)8s] %(name)s:%(lineno)d - %(message)s"
```

**Environment**: `ZSCALER_LOG_FORMAT`

#### `max_file_size`
Maximum log file size in MB before rotation.

```yaml
max_file_size: 10   # Default - rotate at 10MB
max_file_size: 0    # No rotation
max_file_size: 50   # Rotate at 50MB
```

**Default**: 10  
**Environment**: `ZSCALER_LOG_MAX_FILE_SIZE`

#### `backup_count`
Number of rotated log files to keep.

```yaml
backup_count: 5   # Keep 5 backup files
backup_count: 0   # No backups
backup_count: 10  # Keep 10 backup files
```

**Default**: 5  
**Environment**: `ZSCALER_LOG_BACKUP_COUNT`

### Defaults Section

#### `csv_file`
Default CSV file path when not specified via command line.

```yaml
csv_file: "./urls.csv"              # Current directory
csv_file: "/data/urls/daily.csv"    # Absolute path
csv_file: ""                        # No default (prompt user)
```

**Environment**: `ZSCALER_CSV_FILE`

#### `target_category`
Default target category name or ID.

```yaml
target_category: "Blocked Sites"    # Category name
target_category: "CUSTOM_01"        # Category ID
target_category: ""                 # Prompt user
```

**Environment**: `ZSCALER_TARGET_CATEGORY`

#### `auto_remove_duplicates`
Automatically remove duplicate URLs without confirmation.

```yaml
auto_remove_duplicates: false  # Prompt for confirmation
auto_remove_duplicates: true   # Remove automatically
```

**Default**: false  
**Environment**: `ZSCALER_AUTO_REMOVE_DUPLICATES`

#### `dry_run`
Default to dry-run mode for safety.

```yaml
dry_run: false  # Normal mode
dry_run: true   # Safe mode - validate only
```

**Default**: false  
**Environment**: `ZSCALER_DRY_RUN`

### CSV Section

#### `encoding`
Expected character encoding of CSV files.

```yaml
encoding: "utf-8"     # Unicode (recommended)
encoding: "latin-1"   # Western European
encoding: "cp1252"    # Windows Western European
encoding: "ascii"     # ASCII only
```

**Default**: "utf-8"  
**Environment**: `ZSCALER_CSV_ENCODING`

#### `delimiter`
CSV field delimiter character.

```yaml
delimiter: ""     # Auto-detect (recommended)
delimiter: ","    # Comma
delimiter: ";"    # Semicolon
delimiter: "\t"   # Tab
```

**Default**: "" (auto-detect)  
**Environment**: `ZSCALER_CSV_DELIMITER`

#### `has_headers`
Whether CSV file contains headers.

```yaml
has_headers: null   # Auto-detect (recommended)
has_headers: true   # Force headers expected
has_headers: false  # Force no headers
```

**Default**: null (auto-detect)  
**Environment**: `ZSCALER_CSV_HAS_HEADERS`

#### `skip_empty_rows`
Skip empty rows in CSV files.

```yaml
skip_empty_rows: true   # Skip empty rows (recommended)
skip_empty_rows: false  # Process empty rows
```

**Default**: true  
**Environment**: `ZSCALER_CSV_SKIP_EMPTY_ROWS`

#### `max_urls`
Maximum number of URLs to process from CSV.

```yaml
max_urls: 0      # No limit (process all)
max_urls: 1000   # Process first 1000 URLs
max_urls: 100    # Process first 100 URLs
```

**Default**: 0 (unlimited)  
**Environment**: `ZSCALER_CSV_MAX_URLS`

## Configuration Validation

The application validates configuration on startup:

```bash
# Test configuration
python zscaler_bulk_url_uploader.py --config config.yaml --dry-run --csv examples/sample_urls.csv
```

Common validation errors:

- **Missing required fields**: `vanity_domain`, `client_id`
- **Invalid file paths**: Private key file not found
- **Invalid ranges**: Batch size outside 1-1000 range
- **Invalid log levels**: Unsupported logging level

## Environment-Specific Configurations

### Development Environment
```yaml
# dev_config.yaml
zscaler:
  vanity_domain: "dev-acme"
  client_id: "dev-client-id"
  private_key_path: "./keys/dev_private_key.pem"

upload:
  batch_size: 10      # Smaller batches for testing
  retry_attempts: 1   # Fail fast during development

logging:
  level: "DEBUG"      # Verbose logging
  file: "dev_uploader.log"

defaults:
  dry_run: true       # Default to dry-run for safety
```

### Production Environment
```yaml
# prod_config.yaml
zscaler:
  vanity_domain: "acme-corp"
  client_id: "prod-client-id"
  private_key_path: "/etc/ssl/private/zscaler_key.pem"

upload:
  batch_size: 200     # Larger batches for efficiency
  retry_attempts: 5   # More resilient in production
  timeout: 120        # Longer timeout for reliability

logging:
  level: "INFO"       # Standard logging
  file: "/var/log/zscaler/uploader.log"
  max_file_size: 50   # Larger log files
  backup_count: 10    # Keep more history

defaults:
  backup_existing: true  # Always backup in production
```

### Testing Environment
```yaml
# test_config.yaml
zscaler:
  vanity_domain: "test-acme"
  client_id: "test-client-id"
  private_key_path: "./test_keys/private_key.pem"

upload:
  batch_size: 5       # Very small batches
  retry_attempts: 0   # No retries - fail fast

logging:
  level: "DEBUG"      # Maximum detail
  file: "test_uploader.log"

defaults:
  dry_run: true       # Always dry-run in tests
  auto_remove_duplicates: true  # Automated testing

csv:
  max_urls: 50        # Limit for faster tests
```

## Advanced Configuration

### Multiple Environment Setup
```bash
# Use different configs per environment
export ENVIRONMENT="production"
python zscaler_bulk_url_uploader.py --config "config_${ENVIRONMENT}.yaml" --csv urls.csv
```

### Configuration Inheritance
```yaml
# base_config.yaml
zscaler: &zscaler_base
  base_url: "https://api.zsapi.net/zia/api/v1"
  audience: "https://api.zscaler.com"

logging: &logging_base
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  max_file_size: 10
  backup_count: 5

# prod_config.yaml
zscaler:
  <<: *zscaler_base
  vanity_domain: "acme-corp"
  client_id: "prod-client-id"

logging:
  <<: *logging_base
  level: "INFO"
  file: "/var/log/zscaler/uploader.log"
```

### Dynamic Configuration Loading
```python
# Custom configuration loader
import os
import yaml
from pathlib import Path

def load_dynamic_config():
    """Load configuration based on environment and runtime conditions."""
    env = os.getenv('ENVIRONMENT', 'development')
    
    # Base configuration
    config_paths = [
        f"config_{env}.yaml",
        f"~/.zscaler/config_{env}.yaml",
        f"/etc/zscaler/config_{env}.yaml"
    ]
    
    for path in config_paths:
        expanded_path = Path(path).expanduser()
        if expanded_path.exists():
            with open(expanded_path, 'r') as f:
                return yaml.safe_load(f)
    
    raise FileNotFoundError(f"No configuration file found for environment: {env}")
```

### Configuration Templates

#### Docker Environment
```yaml
# docker_config.yaml
zscaler:
  vanity_domain: "${ZSCALER_DOMAIN}"
  client_id: "${ZSCALER_CLIENT_ID}"
  private_key_path: "/app/certs/private_key.pem"

upload:
  batch_size: 100
  retry_attempts: 3
  timeout: 60

logging:
  level: "${LOG_LEVEL:-INFO}"
  file: "/app/logs/zscaler_uploader.log"
  
csv:
  encoding: "utf-8"
  max_urls: "${CSV_MAX_URLS:-0}"
```

#### Kubernetes ConfigMap
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: zscaler-uploader-config
data:
  config.yaml: |
    zscaler:
      vanity_domain: "company"
      client_id: "12345678-abcd-1234-efgh-123456789012"
      private_key_path: "/etc/ssl/private/zscaler_key.pem"
      base_url: "https://api.zsapi.net/zia/api/v1"
      
    upload:
      batch_size: 100
      retry_attempts: 3
      timeout: 60
      backup_existing: true
      
    logging:
      level: "INFO"
      file: "/var/log/zscaler/uploader.log"
      format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
```

## Configuration Security

### Secrets Management

#### Using Azure Key Vault
```bash
# Set up Azure Key Vault integration
export AZURE_KEY_VAULT_NAME="my-keyvault"
export ZSCALER_CLIENT_SECRET="@Microsoft.KeyVault(SecretUri=https://my-keyvault.vault.azure.net/secrets/zscaler-client-secret/)"
```

#### Using AWS Secrets Manager
```bash
# AWS Secrets Manager integration
export ZSCALER_CLIENT_SECRET="arn:aws:secretsmanager:us-east-1:123456789012:secret:zscaler/client-secret"
```

#### Using HashiCorp Vault
```bash
# HashiCorp Vault integration
export VAULT_ADDR="https://vault.company.com"
export VAULT_TOKEN="s.abc123def456"
export ZSCALER_CLIENT_SECRET="vault:secret/data/zscaler#client_secret"
```

### File Permissions
```bash
# Secure configuration file permissions
chmod 600 config.yaml
chmod 600 private_key.pem
chown zscaler:zscaler config.yaml private_key.pem

# Directory permissions
chmod 750 ~/.zscaler/
chmod 750 /etc/zscaler/
```

### Configuration Encryption
```python
# Example: Encrypt sensitive configuration sections
from cryptography.fernet import Fernet

def encrypt_config_section(config_section, key):
    """Encrypt sensitive configuration data."""
    f = Fernet(key)
    serialized = json.dumps(config_section).encode()
    encrypted = f.encrypt(serialized)
    return encrypted.decode()

def decrypt_config_section(encrypted_data, key):
    """Decrypt sensitive configuration data."""
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_data.encode())
    return json.loads(decrypted.decode())
```

## Troubleshooting Configuration

### Common Issues

#### Configuration Not Found
```bash
# Check configuration search paths
python zscaler_bulk_url_uploader.py --help-config

# Enable verbose logging to see config loading
python zscaler_bulk_url_uploader.py --verbose --dry-run
```

#### Environment Variable Override
```bash
# List all Zscaler-related environment variables
env | grep ZSCALER_

# Clear environment variables if needed
unset $(env | grep ZSCALER_ | cut -d= -f1)
```

#### YAML Syntax Errors
```bash
# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Check for common YAML issues
yamllint config.yaml
```

### Configuration Debugging

#### Debug Mode
```yaml
# Enable debug mode in configuration
logging:
  level: "DEBUG"
  
debug:
  show_config: true      # Print loaded configuration
  show_env_vars: true    # Print environment variables
  validate_ssl: false    # Disable SSL validation for testing
```

#### Configuration Validation Script
```python
#!/usr/bin/env python3
"""Configuration validation script."""

import sys
from zscaler_bulk_uploader import load_config, setup_logging

def validate_config(config_path=None):
    """Validate configuration and report issues."""
    try:
        config = load_config(config_path)
        logger = setup_logging(config)
        
        # Check required fields
        required_fields = ['zscaler.vanity_domain', 'zscaler.client_id']
        for field in required_fields:
            if not get_nested_config(config, field):
                print(f"ERROR: Missing required field: {field}")
                return False
        
        # Validate ranges
        batch_size = config.get('upload', {}).get('batch_size', 100)
        if not 1 <= batch_size <= 1000:
            print(f"ERROR: batch_size must be between 1-1000, got: {batch_size}")
            return False
        
        print("✓ Configuration is valid")
        return True
        
    except Exception as e:
        print(f"ERROR: Configuration validation failed: {e}")
        return False

if __name__ == "__main__":
    config_path = sys.argv[1] if len(sys.argv) > 1 else None
    success = validate_config(config_path)
    sys.exit(0 if success else 1)
```

## Configuration Best Practices

### Development Best Practices
1. Use separate configuration files for each environment
2. Never commit secrets to version control
3. Use environment variables for sensitive data
4. Validate configuration before deployment
5. Use configuration templates for consistency

### Production Best Practices
1. Store configurations in secure, version-controlled locations
2. Use encrypted storage for sensitive values
3. Implement proper access controls and audit logging
4. Use configuration management tools (Ansible, Terraform)
5. Monitor configuration changes and their impact

### Security Best Practices
1. Rotate certificates and secrets regularly
2. Use principle of least privilege for API permissions
3. Implement proper logging and monitoring
4. Encrypt configuration files containing sensitive data
5. Use secure secret management solutions

### Maintenance Best Practices
1. Document all configuration options and their purposes
2. Use configuration validation in CI/CD pipelines
3. Implement configuration backup and restore procedures
4. Monitor configuration drift in production
5. Regularly review and update configurations

## Migration Guide

### Migrating from Legacy Configuration
```python
# Legacy configuration format migration
def migrate_legacy_config(old_config):
    """Migrate from legacy configuration format."""
    new_config = {
        'zscaler': {
            'vanity_domain': old_config.get('domain'),
            'client_id': old_config.get('client_id'),
            'private_key_path': old_config.get('key_path'),
            'base_url': old_config.get('api_url', 'https://api.zsapi.net/zia/api/v1')
        },
        'upload': {
            'batch_size': old_config.get('batch_size', 100),
            'retry_attempts': old_config.get('retries', 3),
            'timeout': old_config.get('timeout', 60)
        },
        'logging': {
            'level': old_config.get('log_level', 'INFO'),
            'file': old_config.get('log_file', 'zscaler_uploader.log')
        }
    }
    return new_config
```

### Version Compatibility
```yaml
# Configuration version header for compatibility
version: "2.0"
compatibility:
  min_version: "1.5.0"
  max_version: "3.0.0"

# Rest of configuration...
zscaler:
  vanity_domain: "company"
  # ...
```

This completes the comprehensive configuration reference documentation for your Zscaler Bulk URL Uploader tool. Both documentation files are now complete and provide thorough coverage of the API reference and configuration options.
