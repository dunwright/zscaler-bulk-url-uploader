#!/usr/bin/env python3
"""
Zscaler Bulk URL Uploader

A professional tool for bulk uploading URLs to Zscaler Internet Access 
custom URL categories with certificate-based authentication.

Author: GitHub Community
License: MIT
Repository: https://github.com/dunwright/zscaler-bulk-url-uploader
"""

import argparse
import csv
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import requests
import yaml
from urllib.parse import urlparse

# Check Python version
if sys.version_info < (3, 7):
    print("❌ This application requires Python 3.7 or higher")
    print(f"Current version: {sys.version}")
    sys.exit(1)

# Import JWT and cryptography libraries
try:
    import jwt
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
except ImportError as e:
    print("❌ Missing required libraries. Please install:")
    print("pip install -r requirements.txt")
    print(f"\nSpecific error: {e}")
    sys.exit(1)

# Version information
__version__ = "1.0.0"
__author__ = "GitHub Community"

# Configuration defaults
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
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'file': 'zscaler_uploader.log'
    }
}


class ZscalerError(Exception):
    """Base exception for Zscaler-related errors"""
    pass


class AuthenticationError(ZscalerError):
    """Authentication-related errors"""
    pass


class APIError(ZscalerError):
    """API-related errors"""
    pass


class ConfigurationError(ZscalerError):
    """Configuration-related errors"""
    pass


def setup_logging(config: Dict) -> logging.Logger:
    """Set up logging configuration"""
    log_config = config.get('logging', DEFAULT_CONFIG['logging'])
    
    # Create logs directory if it doesn't exist
    log_file = Path(log_config['file'])
    log_file.parent.mkdir(exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_config['level'].upper()),
        format=log_config['format'],
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info(f"Zscaler Bulk URL Uploader v{__version__} started")
    return logger


def load_config(config_path: Optional[str] = None) -> Dict:
    """Load configuration from file or use defaults"""
    config = DEFAULT_CONFIG.copy()
    
    # Default config file locations
    config_files = [
        config_path,
        'config.yaml',
        'config.yml',
        os.path.expanduser('~/.zscaler/config.yaml'),
        '/etc/zscaler/config.yaml'
    ]
    
    for config_file in config_files:
        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    user_config = yaml.safe_load(f)
                    if user_config:
                        # Deep merge configuration
                        for section, values in user_config.items():
                            if section in config and isinstance(values, dict):
                                config[section].update(values)
                            else:
                                config[section] = values
                logging.info(f"Loaded configuration from {config_file}")
                break
            except Exception as e:
                logging.warning(f"Failed to load config from {config_file}: {e}")
    
    return config


class ZscalerURLUploader:
    """Main class for Zscaler URL upload operations"""
    
    def __init__(self, config: Dict, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.base_url = config['zscaler']['base_url']
        self.token_url_template = config['zscaler']['token_url_template']
        self.audience = config['zscaler']['audience']
        self.access_token = None
        self.token_expiry = None
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': f'ZscalerBulkUploader/{__version__}'
        })
    
    def load_private_key(self, key_path: str, password: Optional[str] = None):
        """Load private key from PEM file with error handling"""
        try:
            key_path = Path(key_path).expanduser().resolve()
            if not key_path.exists():
                raise FileNotFoundError(f"Private key file not found: {key_path}")
            
            self.logger.info(f"Loading private key from {key_path}")
            with open(key_path, 'rb') as key_file:
                private_key = load_pem_private_key(
                    key_file.read(),
                    password=password.encode() if password else None
                )
            self.logger.info("Private key loaded successfully")
            return private_key
            
        except Exception as e:
            self.logger.error(f"Failed to load private key: {e}")
            raise AuthenticationError(f"Failed to load private key: {e}")
    
    def create_jwt_assertion(self, client_id: str, private_key, vanity_domain: str) -> str:
        """Create JWT assertion for client authentication"""
        try:
            now = int(time.time())
            token_url = self.token_url_template.format(vanity_domain=vanity_domain)
            
            payload = {
                'iss': client_id,
                'sub': client_id,
                'aud': token_url,
                'jti': str(uuid.uuid4()),
                'exp': now + 300,  # 5 minutes
                'iat': now,
                'nbf': now
            }
            
            token = jwt.encode(payload, private_key, algorithm='RS256')
            self.logger.debug("JWT assertion created successfully")
            return token
            
        except Exception as e:
            self.logger.error(f"Failed to create JWT assertion: {e}")
            raise AuthenticationError(f"Failed to create JWT assertion: {e}")
    
    def authenticate_with_certificate(self, vanity_domain: str, client_id: str, 
                                    private_key_path: str, key_password: Optional[str] = None) -> bool:
        """Authenticate using certificate-based authentication"""
        try:
            self.logger.info("Starting certificate-based authentication")
            
            # Load private key
            private_key = self.load_private_key(private_key_path, key_password)
            
            # Create JWT assertion
            jwt_assertion = self.create_jwt_assertion(client_id, private_key, vanity_domain)
            
            # Prepare authentication request
            token_url = self.token_url_template.format(vanity_domain=vanity_domain)
            payload = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_assertion": jwt_assertion,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "audience": self.audience
            }
            
            self.logger.info(f"Requesting access token from {token_url}")
            response = self.session.post(
                token_url,
                data=payload,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=self.config['upload']['timeout']
            )
            
            if response.status_code == 200:
                token_data = response.json()
                self.access_token = token_data.get('access_token')
                expires_in = token_data.get('expires_in', 3600)
                self.token_expiry = time.time() + expires_in
                
                self.session.headers['Authorization'] = f"Bearer {self.access_token}"
                
                self.logger.info(f"Authentication successful, token expires in {expires_in}s")
                return True
            else:
                error_msg = f"Authentication failed: {response.status_code}"
                self.logger.error(f"{error_msg} - {response.text}")
                raise AuthenticationError(error_msg)
                
        except AuthenticationError:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected authentication error: {e}")
            raise AuthenticationError(f"Authentication failed: {e}")
    
    def authenticate_with_secret(self, vanity_domain: str, client_id: str, client_secret: str) -> bool:
        """Authenticate using client secret (fallback method)"""
        try:
            self.logger.info("Starting client secret authentication")
            self.logger.warning("Client secret authentication is less secure than certificate-based auth")
            
            token_url = self.token_url_template.format(vanity_domain=vanity_domain)
            payload = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "audience": self.audience
            }
            
            response = self.session.post(
                token_url,
                data=payload,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=self.config['upload']['timeout']
            )
            
            if response.status_code == 200:
                token_data = response.json()
                self.access_token = token_data.get('access_token')
                expires_in = token_data.get('expires_in', 3600)
                self.token_expiry = time.time() + expires_in
                
                self.session.headers['Authorization'] = f"Bearer {self.access_token}"
                
                self.logger.info(f"Authentication successful, token expires in {expires_in}s")
                return True
            else:
                error_msg = f"Authentication failed: {response.status_code}"
                self.logger.error(f"{error_msg} - {response.text}")
                raise AuthenticationError(error_msg)
                
        except AuthenticationError:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected authentication error: {e}")
            raise AuthenticationError(f"Authentication failed: {e}")
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request with error handling and retries"""
        url = f"{self.base_url}{endpoint}"
        retry_attempts = self.config['upload']['retry_attempts']
        
        for attempt in range(retry_attempts + 1):
            try:
                # Check token expiry
                if self.token_expiry and time.time() >= self.token_expiry - 60:
                    self.logger.warning("Access token near expiry, consider re-authentication")
                
                response = self.session.request(
                    method, url, timeout=self.config['upload']['timeout'], **kwargs
                )
                
                # Log request details
                self.logger.debug(f"{method} {url} - Status: {response.status_code}")
                
                if response.status_code < 400:
                    return response
                
                # Handle specific error codes
                if response.status_code == 401:
                    raise AuthenticationError("Authentication failed or token expired")
                elif response.status_code == 403:
                    raise APIError("Insufficient permissions")
                elif response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    self.logger.warning(f"Rate limited, waiting {retry_after}s")
                    time.sleep(retry_after)
                    continue
                else:
                    raise APIError(f"API request failed: {response.status_code} - {response.text}")
                    
            except (requests.RequestException, AuthenticationError, APIError) as e:
                if attempt < retry_attempts:
                    wait_time = 2 ** attempt  # Exponential backoff
                    self.logger.warning(f"Request failed (attempt {attempt + 1}), retrying in {wait_time}s: {e}")
                    time.sleep(wait_time)
                else:
                    self.logger.error(f"Request failed after {retry_attempts + 1} attempts: {e}")
                    raise
        
        raise APIError("Max retry attempts exceeded")
    
    def get_custom_categories(self) -> List[Dict]:
        """Get all custom URL categories"""
        try:
            self.logger.info("Fetching custom URL categories")
            
            response = self._make_request('GET', '/urlCategories/lite')
            all_categories = response.json()
            
            # Filter for custom categories
            custom_categories = [
                cat for cat in all_categories 
                if cat.get('configuredName') and cat.get('configuredName').strip()
            ]
            
            self.logger.info(f"Found {len(custom_categories)} custom URL categories")
            return custom_categories
            
        except Exception as e:
            self.logger.error(f"Failed to fetch categories: {e}")
            raise APIError(f"Failed to fetch categories: {e}")
    
    def get_category_details(self, category_id: str) -> Optional[Dict]:
        """Get detailed information about a specific category"""
        try:
            self.logger.info(f"Fetching details for category {category_id}")
            
            response = self._make_request('GET', f'/urlCategories/{category_id}')
            category_details = response.json()
            
            self.logger.debug(f"Category {category_id} has {len(category_details.get('urls', []))} URLs")
            return category_details
            
        except Exception as e:
            self.logger.error(f"Failed to fetch category details: {e}")
            raise APIError(f"Failed to fetch category details: {e}")
    
    def add_urls_to_category(self, category_id: str, urls: List[str]) -> bool:
        """Add URLs to a category using incremental update"""
        try:
            self.logger.info(f"Adding {len(urls)} URLs to category {category_id}")
            
            # Split into batches if needed
            batch_size = self.config['upload']['batch_size']
            if len(urls) > batch_size:
                self.logger.info(f"Splitting {len(urls)} URLs into batches of {batch_size}")
                
                for i in range(0, len(urls), batch_size):
                    batch = urls[i:i + batch_size]
                    self.logger.info(f"Processing batch {i//batch_size + 1} ({len(batch)} URLs)")
                    
                    payload = {"urls": batch}
                    response = self._make_request(
                        'PUT', 
                        f'/urlCategories/{category_id}?action=ADD_TO_LIST',
                        json=payload
                    )
                    
                    self.logger.info(f"Batch {i//batch_size + 1} uploaded successfully")
            else:
                payload = {"urls": urls}
                response = self._make_request(
                    'PUT', 
                    f'/urlCategories/{category_id}?action=ADD_TO_LIST',
                    json=payload
                )
            
            self.logger.info("All URLs added successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add URLs: {e}")
            raise APIError(f"Failed to add URLs: {e}")
    
    def activate_changes(self) -> bool:
        """Activate configuration changes"""
        try:
            self.logger.info("Activating configuration changes")
            
            response = self._make_request('POST', '/status/activate')
            
            self.logger.info("Configuration activated successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to activate configuration: {e}")
            raise APIError(f"Failed to activate configuration: {e}")


def clean_url(url: str) -> str:
    """Clean URL by removing prefixes and whitespace"""
    if not url:
        return ""
    
    url = url.strip()
    
    # Remove http:// and https:// prefixes
    for prefix in ['https://', 'http://']:
        if url.lower().startswith(prefix):
            url = url[len(prefix):]
            break
    
    return url.strip()


def validate_url(url: str) -> bool:
    """Basic URL validation"""
    if not url or not url.strip():
        return False
    
    cleaned = clean_url(url)
    
    # Basic checks
    if not cleaned or '.' not in cleaned:
        return False
    
    # Check for invalid characters
    invalid_chars = ['<', '>', '"', '|', '^', '`', '{', '}', '\\']
    if any(char in cleaned for char in invalid_chars):
        return False
    
    return True


def parse_csv_file(file_path: str, logger: logging.Logger) -> List[str]:
    """Parse CSV file and extract URLs with validation"""
    urls = []
    invalid_urls = []
    
    try:
        file_path = Path(file_path).resolve()
        if not file_path.exists():
            raise FileNotFoundError(f"CSV file not found: {file_path}")
        
        logger.info(f"Parsing CSV file: {file_path}")
        
        with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
            # Auto-detect CSV format
            sample = csvfile.read(1024)
            csvfile.seek(0)
            
            try:
                sniffer = csv.Sniffer()
                delimiter = sniffer.sniff(sample).delimiter
                has_header = sniffer.has_header(sample)
            except:
                delimiter = ','
                has_header = False
            
            reader = csv.reader(csvfile, delimiter=delimiter)
            
            # Skip header if present
            if has_header:
                headers = next(reader, None)
                logger.debug(f"CSV headers detected: {headers}")
            
            for row_num, row in enumerate(reader, start=1):
                for col_num, cell in enumerate(row):
                    if cell and cell.strip():
                        cleaned_url = clean_url(cell)
                        if validate_url(cleaned_url):
                            urls.append(cleaned_url)
                        else:
                            invalid_urls.append((row_num, col_num, cell))
        
        # Remove duplicates while preserving order
        seen = set()
        unique_urls = []
        duplicates = 0
        
        for url in urls:
            url_lower = url.lower()
            if url_lower not in seen:
                seen.add(url_lower)
                unique_urls.append(url)
            else:
                duplicates += 1
        
        logger.info(f"Parsed {len(unique_urls)} unique valid URLs from CSV")
        if duplicates > 0:
            logger.info(f"Removed {duplicates} duplicate URLs")
        if invalid_urls:
            logger.warning(f"Found {len(invalid_urls)} invalid URLs (skipped)")
            for row, col, url in invalid_urls[:5]:  # Log first 5
                logger.warning(f"Invalid URL at row {row}, col {col}: {url}")
        
        return unique_urls
        
    except Exception as e:
        logger.error(f"Failed to parse CSV file: {e}")
        raise ConfigurationError(f"Failed to parse CSV file: {e}")


def create_sample_config() -> str:
    """Create a sample configuration file"""
    config_content = """# Zscaler Bulk URL Uploader Configuration

zscaler:
  # Your Zscaler vanity domain (e.g., 'company' for company.zslogin.net)
  vanity_domain: "your-company"
  
  # OAuth Client ID from ZIdentity Admin Portal
  client_id: "your-client-id"
  
  # Path to private key file for certificate authentication
  private_key_path: "./private_key.pem"
  
  # Private key password (if encrypted, otherwise leave empty)
  private_key_password: ""
  
  # Alternative: Client Secret (less secure than certificate auth)
  # client_secret: "your-client-secret"

upload:
  # Number of URLs to upload in each batch
  batch_size: 100
  
  # Number of retry attempts for failed requests
  retry_attempts: 3
  
  # Request timeout in seconds
  timeout: 60
  
  # Create backup of existing URLs before upload
  backup_existing: true

logging:
  # Log level: DEBUG, INFO, WARNING, ERROR
  level: "INFO"
  
  # Log file path
  file: "zscaler_uploader.log"
  
  # Log format
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
"""
    
    config_path = Path("config.yaml")
    with open(config_path, 'w') as f:
        f.write(config_content)
    
    return str(config_path)


def interactive_setup(logger: logging.Logger) -> Dict:
    """Interactive setup for authentication details"""
    print("\n🔐 Authentication Setup")
    print("=" * 40)
    
    # Choose authentication method
    print("\nAuthentication Methods:")
    print("1. Certificate/Private Key (Recommended - Most Secure)")
    print("2. Client Secret (Less Secure)")
    
    while True:
        choice = input("Select authentication method (1-2): ").strip()
        if choice in ['1', '2']:
            break
        print("Please enter '1' or '2'")
    
    # Get basic details
    vanity_domain = input("Enter your Zscaler vanity domain: ").strip()
    client_id = input("Enter your Client ID: ").strip()
    
    auth_config = {
        'vanity_domain': vanity_domain,
        'client_id': client_id
    }
    
    if choice == '1':
        print("\n💡 Certificate authentication selected")
        private_key_path = input("Enter path to private key file (.pem): ").strip()
        
        # Check if file exists
        if not Path(private_key_path).exists():
            logger.error(f"Private key file not found: {private_key_path}")
            raise ConfigurationError(f"Private key file not found: {private_key_path}")
        
        # Check if key is password protected
        key_password = input("Enter private key password (or press Enter if none): ").strip()
        
        auth_config.update({
            'method': 'certificate',
            'private_key_path': private_key_path,
            'private_key_password': key_password if key_password else None
        })
    else:
        print("\n⚠️  Client secret authentication selected (less secure)")
        client_secret = input("Enter your Client Secret: ").strip()
        auth_config.update({
            'method': 'secret',
            'client_secret': client_secret
        })
    
    return auth_config


def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(
        description="Zscaler Bulk URL Uploader - Upload URLs to custom categories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --csv urls.csv --config config.yaml
  %(prog)s --generate-config
  %(prog)s --help-auth
        """
    )
    
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('--config', '-c', help='Configuration file path')
    parser.add_argument('--csv', help='CSV file containing URLs to upload')
    parser.add_argument('--category', help='Target URL category name or ID')
    parser.add_argument('--dry-run', action='store_true', help='Validate inputs without uploading')
    parser.add_argument('--generate-config', action='store_true', help='Generate sample configuration file')
    parser.add_argument('--help-auth', action='store_true', help='Show authentication setup help')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Handle special commands
    if args.generate_config:
        config_path = create_sample_config()
        print(f"✅ Sample configuration created: {config_path}")
        print("Edit the file with your Zscaler details and run again.")
        return
    
    if args.help_auth:
        print("\n📋 Authentication Setup Help")
        print("=" * 50)
        print("1. Generate private key:")
        print("   openssl genrsa -out private_key.pem 2048")
        print("\n2. Generate certificate:")
        print("   openssl req -new -x509 -key private_key.pem -out certificate.pem -days 365")
        print("\n3. Upload certificate.pem to Zscaler ZIdentity Admin Portal")
        print("4. Use private_key.pem with this application")
        print("\n5. Run: python zscaler_bulk_url_uploader.py --generate-config")
        return
    
    try:
        # Load configuration
        config = load_config(args.config)
        
        # Adjust logging level if verbose
        if args.verbose:
            config['logging']['level'] = 'DEBUG'
        
        # Set up logging
        logger = setup_logging(config)
        
        print(f"🚀 Zscaler Bulk URL Uploader v{__version__}")
        print(f"🐍 Python {sys.version.split()[0]} detected")
        print("=" * 50)
        
        # Get CSV file
        csv_file = args.csv
        if not csv_file:
            csv_file = input("Enter path to CSV file: ").strip()
        
        if not csv_file or not Path(csv_file).exists():
            logger.error("CSV file not found or not specified")
            return 1
        
        # Parse CSV file
        urls_to_upload = parse_csv_file(csv_file, logger)
        
        if not urls_to_upload:
            logger.error("No valid URLs found in CSV file")
            return 1
        
        print(f"📊 Found {len(urls_to_upload)} URLs to upload")
        
        if args.dry_run:
            print("🔍 Dry run mode - validation complete, no upload performed")
            return 0
        
        # Initialize uploader
        uploader = ZscalerURLUploader(config, logger)
        
        # Get authentication details
        auth_config = None
        if config.get('zscaler', {}).get('vanity_domain'):
            # Use config file auth
            zscaler_config = config['zscaler']
            if zscaler_config.get('private_key_path'):
                auth_config = {
                    'method': 'certificate',
                    'vanity_domain': zscaler_config['vanity_domain'],
                    'client_id': zscaler_config['client_id'],
                    'private_key_path': zscaler_config['private_key_path'],
                    'private_key_password': zscaler_config.get('private_key_password')
                }
            elif zscaler_config.get('client_secret'):
                auth_config = {
                    'method': 'secret',
                    'vanity_domain': zscaler_config['vanity_domain'],
                    'client_id': zscaler_config['client_id'],
                    'client_secret': zscaler_config['client_secret']
                }
        
        if not auth_config:
            auth_config = interactive_setup(logger)
        
        # Authenticate
        if auth_config['method'] == 'certificate':
            success = uploader.authenticate_with_certificate(
                auth_config['vanity_domain'],
                auth_config['client_id'],
                auth_config['private_key_path'],
                auth_config.get('private_key_password')
            )
        else:
            success = uploader.authenticate_with_secret(
                auth_config['vanity_domain'],
                auth_config['client_id'],
                auth_config['client_secret']
            )
        
        if not success:
            logger.error("Authentication failed")
            return 1
        
        # Get categories and let user select
        categories = uploader.get_custom_categories()
        
        if not categories:
            logger.error("No custom URL categories found")
            return 1
        
        # Category selection logic here...
        # (This would continue with the interactive category selection)
        
        logger.info("Setup completed successfully - ready for URL upload")
        return 0
        
    except KeyboardInterrupt:
        print("\n👋 Operation interrupted by user")
        return 130
    except (ZscalerError, ConfigurationError) as e:
        print(f"❌ {e}")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        logging.exception("Unexpected error occurred")
        return 1


if __name__ == "__main__":
    sys.exit(main())
