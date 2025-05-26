# API Reference

Technical reference for the Zscaler Bulk URL Uploader API components.

## Module Overview

The application is structured into several key components:

- **Authentication**: OAuth 2.0 with certificate or secret-based auth
- **Configuration**: YAML-based configuration management
- **CSV Processing**: Flexible CSV parsing and URL validation
- **API Client**: Zscaler Internet Access API interaction
- **Logging**: Comprehensive logging and error handling

## Core Classes

### ZscalerURLUploader

Main class for interacting with Zscaler Internet Access API.

```python
class ZscalerURLUploader:
    def __init__(self, config: Dict, logger: logging.Logger)
```

#### Parameters
- `config` (Dict): Configuration dictionary
- `logger` (logging.Logger): Logger instance

#### Methods

##### authenticate_with_certificate()
```python
def authenticate_with_certificate(
    self, 
    vanity_domain: str, 
    client_id: str, 
    private_key_path: str, 
    key_password: Optional[str] = None
) -> bool
```

Authenticate using certificate-based authentication.

**Parameters:**
- `vanity_domain` (str): Zscaler vanity domain (without .zslogin.net)
- `client_id` (str): OAuth client ID from ZIdentity
- `private_key_path` (str): Path to private key file
- `key_password` (Optional[str]): Private key password if encrypted

**Returns:**
- `bool`: True if authentication successful

**Raises:**
- `AuthenticationError`: If authentication fails
- `FileNotFoundError`: If private key file not found

**Example:**
```python
uploader = ZscalerURLUploader(config, logger)
success = uploader.authenticate_with_certificate(
    "company",
    "client-id",
    "./private_key.pem"
)
```

##### authenticate_with_secret()
```python
def authenticate_with_secret(
    self, 
    vanity_domain: str, 
    client_id: str, 
    client_secret: str
) -> bool
```

Authenticate using client secret.

**Parameters:**
- `vanity_domain` (str): Zscaler vanity domain
- `client_id` (str): OAuth client ID
- `client_secret` (str): Client secret

**Returns:**
- `bool`: True if authentication successful

**Example:**
```python
success = uploader.authenticate_with_secret(
    "company",
    "client-id", 
    "client-secret"
)
```

##### get_custom_categories()
```python
def get_custom_categories(self) -> List[Dict]
```

Retrieve all custom URL categories.

**Returns:**
- `List[Dict]`: List of custom URL category objects

**Raises:**
- `APIError`: If API request fails

**Example:**
```python
categories = uploader.get_custom_categories()
for category in categories:
    print(f"ID: {category['id']}, Name: {category['configuredName']}")
```

##### get_category_details()
```python
def get_category_details(self, category_id: str) -> Optional[Dict]
```

Get detailed information about a specific category.

**Parameters:**
- `category_id` (str): Category ID

**Returns:**
- `Optional[Dict]`: Category details or None if not found

**Example:**
```python
details = uploader.get_category_details("CUSTOM_01")
existing_urls = details.get('urls', [])
```

##### add_urls_to_category()
```python
def add_urls_to_category(self, category_id: str, urls: List[str]) -> bool
```

Add URLs to a category using incremental update.

**Parameters:**
- `category_id` (str): Target category ID
- `urls` (List[str]): List of URLs to add

**Returns:**
- `bool`: True if successful

**Raises:**
- `APIError`: If API request fails

**Example:**
```python
urls = ["example.com", "test.com"]
success = uploader.add_urls_to_category("CUSTOM_01", urls)
```

##### activate_changes()
```python
def activate_changes(self) -> bool
```

Activate configuration changes in Zscaler.

**Returns:**
- `bool`: True if activation successful

**Example:**
```python
if uploader.activate_changes():
    print("Configuration activated successfully")
```

## Utility Functions

### clean_url()
```python
def clean_url(url: str) -> str
```

Clean URL by removing prefixes and whitespace.

**Parameters:**
- `url` (str): Raw URL string

**Returns:**
- `str`: Cleaned URL

**Example:**
```python
cleaned = clean_url("https://example.com")  # Returns: "example.com"
```

### validate_url()
```python
def validate_url(url: str) -> bool
```

Validate URL format.

**Parameters:**
- `url` (str): URL to validate

**Returns:**
- `bool`: True if valid URL format

**Example:**
```python
is_valid = validate_url("example.com")  # Returns: True
is_valid = validate_url("not-a-url")    # Returns: False
```

### parse_csv_file()
```python
def parse_csv_file(file_path: str, logger: logging.Logger) -> List[str]
```

Parse CSV file and extract URLs.

**Parameters:**
- `file_path` (str): Path to CSV file
- `logger` (logging.Logger): Logger instance

**Returns:**
- `List[str]`: List of unique, validated URLs

**Raises:**
- `ConfigurationError`: If file cannot be parsed

**Example:**
```python
urls = parse_csv_file("urls.csv", logger)
print(f"Found {len(urls)} URLs")
```

### load_config()
```python
def load_config(config_path: Optional[str] = None) -> Dict
```

Load configuration from file or defaults.

**Parameters:**
- `config_path` (Optional[str]): Path to config file

**Returns:**
- `Dict`: Configuration dictionary

**Example:**
```python
config = load_config("config.yaml")
```

### setup_logging()
```python
def setup_logging(config: Dict) -> logging.Logger
```

Set up logging configuration.

**Parameters:**
- `config` (Dict): Configuration dictionary containing logging settings

**Returns:**
- `logging.Logger`: Configured logger instance

**Example:**
```python
config = load_config()
logger = setup_logging(config)
logger.info("Application started")
```

## Exception Classes

### AuthenticationError
```python
class AuthenticationError(Exception):
    """Raised when authentication with Zscaler API fails."""
    pass
```

### APIError
```python
class APIError(Exception):
    """Raised when Zscaler API returns an error response."""
    pass
```

### ConfigurationError
```python
class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing."""
    pass
```

### CSVParsingError
```python
class CSVParsingError(Exception):
    """Raised when CSV file cannot be parsed or contains invalid data."""
    pass
```

## Constants

### Default Configuration Values
```python
DEFAULT_CONFIG = {
    'zscaler': {
        'base_url': 'https://api.zsapi.net/zia/api/v1',
        'token_url_template': 'https://{vanity_domain}.zslogin.net/oauth2/v1/token',
        'audience': 'https://api.zscaler.com'
    },
    'upload': {
        'batch_size': 100,
        'retry_attempts': 3,
        'timeout': 60,
        'backup_existing': True
    },
    'logging': {
        'level': 'INFO',
        'file': 'zscaler_uploader.log',
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'max_file_size': 10,
        'backup_count': 5
    }
}
```

### API Endpoints
```python
ENDPOINTS = {
    'categories': '/urlCategories',
    'custom_categories': '/urlCategories/lite',
    'category_details': '/urlCategories/{category_id}',
    'activate': '/status/activate'
}
```

### HTTP Status Codes
```python
HTTP_STATUS = {
    'OK': 200,
    'CREATED': 201,
    'NO_CONTENT': 204,
    'BAD_REQUEST': 400,
    'UNAUTHORIZED': 401,
    'FORBIDDEN': 403,
    'NOT_FOUND': 404,
    'TOO_MANY_REQUESTS': 429,
    'INTERNAL_SERVER_ERROR': 500
}
```

## Usage Patterns

### Basic Usage Pattern
```python
from zscaler_bulk_uploader import ZscalerURLUploader, load_config, setup_logging

# Load configuration
config = load_config("config.yaml")
logger = setup_logging(config)

# Initialize uploader
uploader = ZscalerURLUploader(config, logger)

# Authenticate
success = uploader.authenticate_with_certificate(
    config['zscaler']['vanity_domain'],
    config['zscaler']['client_id'],
    config['zscaler']['private_key_path']
)

if success:
    # Get categories and upload URLs
    categories = uploader.get_custom_categories()
    urls = ["example.com", "test.com"]
    uploader.add_urls_to_category("CUSTOM_01", urls)
    uploader.activate_changes()
```

### Error Handling Pattern
```python
try:
    uploader = ZscalerURLUploader(config, logger)
    uploader.authenticate_with_certificate(vanity_domain, client_id, key_path)
    uploader.add_urls_to_category(category_id, urls)
    uploader.activate_changes()
except AuthenticationError as e:
    logger.error(f"Authentication failed: {e}")
except APIError as e:
    logger.error(f"API error: {e}")
except ConfigurationError as e:
    logger.error(f"Configuration error: {e}")
except Exception as e:
    logger.error(f"Unexpected error: {e}")
```

### Batch Processing Pattern
```python
def upload_urls_in_batches(uploader, category_id, urls, batch_size=100):
    """Upload URLs in batches with error handling."""
    total_urls = len(urls)
    successful_uploads = 0
    
    for i in range(0, total_urls, batch_size):
        batch = urls[i:i + batch_size]
        try:
            success = uploader.add_urls_to_category(category_id, batch)
            if success:
                successful_uploads += len(batch)
                logger.info(f"Uploaded batch {i//batch_size + 1}: {len(batch)} URLs")
            else:
                logger.warning(f"Failed to upload batch {i//batch_size + 1}")
        except APIError as e:
            logger.error(f"API error in batch {i//batch_size + 1}: {e}")
    
    return successful_uploads
```

## Integration Examples

### Command Line Integration
```python
import argparse

def main():
    parser = argparse.ArgumentParser(description='Bulk upload URLs to Zscaler')
    parser.add_argument('--csv', required=True, help='CSV file with URLs')
    parser.add_argument('--category', required=True, help='Target category')
    parser.add_argument('--config', help='Configuration file')
    parser.add_argument('--dry-run', action='store_true', help='Validate only')
    
    args = parser.parse_args()
    
    config = load_config(args.config)
    logger = setup_logging(config)
    
    # Process CSV and upload
    urls = parse_csv_file(args.csv, logger)
    
    if args.dry_run:
        logger.info(f"Dry run: would upload {len(urls)} URLs to {args.category}")
        return
    
    uploader = ZscalerURLUploader(config, logger)
    # ... rest of implementation
```

### Configuration Management
```python
def merge_configs(*configs):
    """Merge multiple configuration dictionaries."""
    merged = {}
    for config in configs:
        for key, value in config.items():
            if isinstance(value, dict) and key in merged:
                merged[key].update(value)
            else:
                merged[key] = value
    return merged

# Usage
default_config = load_config()
user_config = load_config("user_config.yaml")
env_config = load_config_from_env()

final_config = merge_configs(default_config, user_config, env_config)
```

## Performance Considerations

### Batch Size Optimization
- **Small batches (10-50)**: Better for unreliable networks, more granular error handling
- **Medium batches (100-200)**: Balanced performance and reliability (recommended)
- **Large batches (500-1000)**: Maximum throughput but higher memory usage

### Rate Limiting
The Zscaler API has rate limits. The uploader implements:
- Exponential backoff on rate limit errors
- Configurable retry attempts
- Request timeout handling

### Memory Usage
For large URL lists:
- URLs are processed in batches to limit memory usage
- Consider splitting very large CSV files (>100k URLs)
- Monitor memory usage during bulk operations

## Security Best Practices

### Certificate Management
- Store private keys securely with proper file permissions (600)
- Use encrypted private keys in production
- Rotate certificates regularly
- Never commit private keys to version control

### Configuration Security
- Use environment variables for sensitive data
- Implement proper access controls on configuration files
- Consider using Azure Key Vault or similar for secrets management
- Enable audit logging for configuration changes

### API Security
- Use certificate-based authentication over client secrets
- Implement proper token management and refresh
- Monitor API usage and unusual patterns
- Follow principle of least privilege for API permissions