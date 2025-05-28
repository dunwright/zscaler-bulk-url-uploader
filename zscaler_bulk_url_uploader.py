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
__version__ = "1.0.1"
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
    
    def add_urls_to_category(self, category_id: str, urls: List[str], category_name: str, url_list_type: str = 'urls') -> bool:
        """Add URLs to a category using incremental update - FIXED VERSION"""
        try:
            self.logger.info(f"Adding {len(urls)} URLs to category {category_id} ({url_list_type} list)")
            self.logger.info(f"URLs to add: {urls}")  # Debug logging
            
            # Split into batches if needed
            batch_size = self.config['upload']['batch_size']
            if len(urls) > batch_size:
                self.logger.info(f"Splitting {len(urls)} URLs into batches of {batch_size}")
                
                for i in range(0, len(urls), batch_size):
                    batch = urls[i:i + batch_size]
                    self.logger.info(f"Processing batch {i//batch_size + 1} ({len(batch)} URLs)")
                    self.logger.info(f"Batch URLs: {batch}")  # Debug logging
                    
                    # FIXED: Include required fields for OneAPI with specified URL list type
                    payload = {
                        "configuredName": category_name,
                        "customCategory": True,
                        url_list_type: batch  # Use dynamic key for URL list type
                    }
                    
                    self.logger.info(f"API Payload: {json.dumps(payload, indent=2)}")  # Debug logging
                    
                    response = self._make_request(
                        'PUT', 
                        f'/urlCategories/{category_id}?action=ADD_TO_LIST',
                        json=payload
                    )
                    
                    self.logger.info(f"Batch {i//batch_size + 1} uploaded successfully")
            else:
                # FIXED: Include required fields for OneAPI with specified URL list type
                payload = {
                    "configuredName": category_name,
                    "customCategory": True,
                    url_list_type: urls  # Use dynamic key for URL list type
                }
                
                self.logger.info(f"API Payload: {json.dumps(payload, indent=2)}")  # Debug logging
                
                response = self._make_request(
                    'PUT', 
                    f'/urlCategories/{category_id}?action=ADD_TO_LIST',
                    json=payload
                )
            
            self.logger.info(f"All URLs added successfully to {url_list_type} list")
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
    """Basic URL validation - supports wildcards and standard domains"""
    if not url or not url.strip():
        return False
    
    cleaned = clean_url(url)
    
    # Handle wildcard domains (starting with .)
    if cleaned.startswith('.'):
        # Wildcard domain: must have at least one dot after the leading dot
        # e.g., .example.com, .wildcard.net
        domain_part = cleaned[1:]  # Remove leading dot
        if not domain_part or '.' not in domain_part:
            return False
        # Check the domain part after the wildcard
        return '.' in domain_part and len(domain_part) > 2
    
    # Regular domain validation
    if not cleaned or '.' not in cleaned:
        return False
    
    # Check for invalid characters
    invalid_chars = ['<', '>', '"', '|', '^', '`', '{', '}', '\\']
    if any(char in cleaned for char in invalid_chars):
        return False
    
    # Basic domain structure check
    parts = cleaned.split('.')
    if len(parts) < 2:
        return False
    
    # Each part should have at least one character
    if any(not part for part in parts):
        return False
    
    return True


def parse_csv_file(file_path: str, logger: logging.Logger) -> List[str]:
    """Parse CSV file and extract URLs with validation - supports multiple formats"""
    urls = []
    invalid_urls = []
    
    try:
        file_path = Path(file_path).resolve()
        if not file_path.exists():
            raise FileNotFoundError(f"CSV file not found: {file_path}")
        
        logger.info(f"Parsing CSV file: {file_path}")
        
        with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
            # Read all content
            content = csvfile.read().strip()
            
            # Split into lines
            lines = [line.strip() for line in content.split('\n') if line.strip()]
            
            if not lines:
                logger.warning("CSV file is empty")
                return []
            
            logger.info(f"Found {len(lines)} non-empty lines in file")
            
            # Smart parsing: handle each line individually
            logger.info("Using flexible parsing (handles mixed formats)")
            
            for line_num, line in enumerate(lines, start=1):
                logger.debug(f"Processing line {line_num}: '{line}'")
                
                # Check if this line contains multiple space-separated URLs
                if ' ' in line and ',' not in line:
                    # Likely space-separated URLs on this line
                    parts = line.split()
                    logger.debug(f"Line {line_num}: Detected {len(parts)} space-separated parts: {parts}")
                    
                    for part_num, part in enumerate(parts, start=1):
                        cleaned_url = clean_url(part)
                        if validate_url(cleaned_url):
                            urls.append(cleaned_url)
                            logger.debug(f"Added URL from line {line_num}, part {part_num}: {cleaned_url}")
                        else:
                            if '.' in part or len(part) > 3:
                                invalid_urls.append((line_num, part_num, part))
                                logger.debug(f"Invalid URL at line {line_num}, part {part_num}: {part}")
                
                elif ',' in line:
                    # Likely CSV format on this line
                    logger.debug(f"Line {line_num}: Detected CSV format")
                    import io
                    reader = csv.reader(io.StringIO(line))
                    try:
                        row = next(reader)
                        for col_num, cell in enumerate(row, start=1):
                            if cell and cell.strip():
                                cleaned_url = clean_url(cell)
                                if validate_url(cleaned_url):
                                    urls.append(cleaned_url)
                                    logger.debug(f"Added URL from line {line_num}, col {col_num}: {cleaned_url}")
                                else:
                                    if '.' in cell or len(cell) > 3:
                                        invalid_urls.append((line_num, col_num, cell))
                    except:
                        # Fall back to treating as single URL
                        cleaned_url = clean_url(line)
                        if validate_url(cleaned_url):
                            urls.append(cleaned_url)
                            logger.debug(f"Added URL from line {line_num} (fallback): {cleaned_url}")
                        else:
                            invalid_urls.append((line_num, 1, line))
                
                else:
                    # Single URL on this line
                    logger.debug(f"Line {line_num}: Detected single URL format")
                    cleaned_url = clean_url(line)
                    if validate_url(cleaned_url):
                        urls.append(cleaned_url)
                        logger.debug(f"Added URL from line {line_num}: {cleaned_url}")
                    else:
                        invalid_urls.append((line_num, 1, line))
        
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
        logger.info(f"Final URL list: {unique_urls}")  # Debug logging
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


def display_categories(categories: List[Dict]) -> None:
    """Display available custom URL categories"""
    print("\n📋 Available Custom URL Categories:")
    print("-" * 60)
    for i, category in enumerate(categories, 1):
        name = category.get('configuredName', 'Unnamed')
        category_id = category.get('id', 'Unknown')
        description = category.get('description', 'No description')
        url_count = category.get('customUrlsCount', 0)
        
        print(f"{i:2d}. {name}")
        print(f"    ID: {category_id}")
        print(f"    Description: {description}")
        print(f"    Current URLs: {url_count}")
        print()


def display_category_details(category_details: Dict, selected_category: Dict) -> None:
    """Display detailed information about a category including both URL lists"""
    custom_urls = category_details.get('urls', [])
    db_categorized_urls = category_details.get('dbCategorizedUrls', [])
    
    print(f"\n📊 Category '{selected_category.get('configuredName')}' Details:")
    print("-" * 60)
    print(f"Custom URLs: {len(custom_urls)}")
    print(f"DB Categorized URLs: {len(db_categorized_urls)}")
    print(f"Total URLs: {len(custom_urls) + len(db_categorized_urls)}")
    
    if custom_urls:
        print(f"\nSample Custom URLs (first 3):")
        for url in custom_urls[:3]:
            print(f"  • {url}")
        if len(custom_urls) > 3:
            print(f"  ... and {len(custom_urls) - 3} more")
    
    if db_categorized_urls:
        print(f"\nSample DB Categorized URLs (first 3):")
        for url in db_categorized_urls[:3]:
            print(f"  • {url}")
        if len(db_categorized_urls) > 3:
            print(f"  ... and {len(db_categorized_urls) - 3} more")


def select_category(categories: List[Dict]) -> Optional[Dict]:
    """Let user select a category from the list"""
    while True:
        try:
            choice = input(f"Select category (1-{len(categories)}) or 'q' to quit: ").strip()
            
            if choice.lower() == 'q':
                return None
            
            choice_num = int(choice)
            if 1 <= choice_num <= len(categories):
                selected = categories[choice_num - 1]
                print(f"✅ Selected: {selected.get('configuredName')}")
                return selected
            else:
                print(f"❌ Please enter a number between 1 and {len(categories)}")
                
        except ValueError:
            print("❌ Please enter a valid number or 'q' to quit")


def choose_url_list_type() -> str:
    """Let user choose which URL list to add URLs to"""
    print("\n📝 URL List Types:")
    print("1. Custom URLs (urls) - Administrator-defined URLs")
    print("2. DB Categorized URLs (dbCategorizedUrls) - URLs that retain parent category")
    print("\nℹ️  Most common choice is 'Custom URLs' for manually curated lists")
    
    while True:
        choice = input("Select URL list type (1-2): ").strip()
        if choice == '1':
            return 'urls'
        elif choice == '2':
            return 'dbCategorizedUrls'
        else:
            print("Please enter '1' or '2'")


def find_duplicates(new_urls: List[str], existing_urls: List[str]) -> List[str]:
    """Find duplicate URLs between new and existing lists"""
    existing_set = set(url.lower() for url in existing_urls)
    duplicates = []
    
    for url in new_urls:
        if url.lower() in existing_set:
            duplicates.append(url)
    
    return duplicates


def check_all_duplicates(new_urls: List[str], category_details: Dict, url_list_type: str) -> Tuple[List[str], List[str]]:
    """
    Check for duplicates in both URL lists and return comprehensive duplicate info
    Returns: (duplicates_in_selected_list, duplicates_in_other_list)
    """
    selected_list_urls = category_details.get(url_list_type, [])
    other_list_type = 'dbCategorizedUrls' if url_list_type == 'urls' else 'urls'
    other_list_urls = category_details.get(other_list_type, [])
    
    # Find duplicates in selected list
    duplicates_in_selected = find_duplicates(new_urls, selected_list_urls)
    
    # Find duplicates in other list
    duplicates_in_other = find_duplicates(new_urls, other_list_urls)
    
    return duplicates_in_selected, duplicates_in_other


def handle_all_duplicates(urls_to_upload: List[str], category_details: Dict, selected_category: Dict, url_list_type: str, logger) -> List[str]:
    """Handle duplicates in both URL lists and return cleaned URL list"""
    duplicates_in_selected, duplicates_in_other = check_all_duplicates(urls_to_upload, category_details, url_list_type)
    
    # Get list type names for display
    selected_list_name = "Custom URLs" if url_list_type == 'urls' else "DB Categorized URLs"
    other_list_type = 'dbCategorizedUrls' if url_list_type == 'urls' else 'urls'
    other_list_name = "DB Categorized URLs" if other_list_type == 'dbCategorizedUrls' else "Custom URLs"
    
    all_duplicates = set()
    
    # Handle duplicates in selected list
    if duplicates_in_selected:
        logger.warning(f"Found {len(duplicates_in_selected)} duplicate URLs in {url_list_type} list")
        print(f"\n⚠️  Found {len(duplicates_in_selected)} URLs already in {selected_list_name} list:")
        print("-" * 60)
        for i, url in enumerate(duplicates_in_selected[:5], 1):
            print(f"{i:2d}. {url}")
        if len(duplicates_in_selected) > 5:
            print(f"    ... and {len(duplicates_in_selected) - 5} more")
        
        print(f"\nThese URLs are already in the target {selected_list_name} list.")
        if input("Remove these duplicates from upload? (y/n): ").strip().lower() in ['y', 'yes']:
            all_duplicates.update(dup.lower() for dup in duplicates_in_selected)
            logger.info(f"Will remove {len(duplicates_in_selected)} duplicates from {url_list_type} list")
        else:
            logger.info(f"Proceeding with duplicates in {url_list_type} list (they will be ignored by Zscaler)")
    
    # Handle duplicates in other list
    if duplicates_in_other:
        logger.warning(f"Found {len(duplicates_in_other)} URLs already in {other_list_type} list")
        print(f"\n⚠️  Found {len(duplicates_in_other)} URLs already in {other_list_name} list:")
        print("-" * 60)
        for i, url in enumerate(duplicates_in_other[:5], 1):
            print(f"{i:2d}. {url}")
        if len(duplicates_in_other) > 5:
            print(f"    ... and {len(duplicates_in_other) - 5} more")
        
        print(f"\nThese URLs exist in the other list ({other_list_name}).")
        print("Adding them to your selected list will create cross-list duplicates.")
        if input("Remove these cross-list duplicates from upload? (y/n): ").strip().lower() in ['y', 'yes']:
            all_duplicates.update(dup.lower() for dup in duplicates_in_other)
            logger.info(f"Will remove {len(duplicates_in_other)} cross-list duplicates")
        else:
            logger.info(f"Proceeding with cross-list duplicates (URLs will exist in both lists)")
    
    # Remove all selected duplicates
    if all_duplicates:
        original_count = len(urls_to_upload)
        urls_to_upload = [url for url in urls_to_upload if url.lower() not in all_duplicates]
        removed_count = original_count - len(urls_to_upload)
        logger.info(f"Removed {removed_count} total duplicates")
        print(f"✅ Removed {removed_count} duplicate URLs from upload list")
    
    return urls_to_upload


def confirm_duplicate_removal(duplicates: List[str]) -> bool:
    """Ask user to confirm removal of duplicate URLs"""
    print(f"\n⚠️  Found {len(duplicates)} duplicate URLs:")
    print("-" * 40)
    for i, url in enumerate(duplicates[:10], 1):  # Show first 10
        print(f"{i:2d}. {url}")
    
    if len(duplicates) > 10:
        print(f"    ... and {len(duplicates) - 10} more")
    
    print()
    while True:
        choice = input("Remove duplicates from upload list? (y/n): ").strip().lower()
        if choice in ['y', 'yes']:
            return True
        elif choice in ['n', 'no']:
            return False
        else:
            print("Please enter 'y' or 'n'")


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
        
        # Determine category selection method
        selected_category = None
        
        # Check if category specified via command line
        if args.category:
            logger.info(f"Looking for category: {args.category}")
            
            # Try to find category by name or ID
            for category in categories:
                if (category.get('configuredName', '').lower() == args.category.lower() or 
                    category.get('id', '').upper() == args.category.upper()):
                    selected_category = category
                    logger.info(f"Found category: {category.get('configuredName')} (ID: {category.get('id')})")
                    break
            
            if not selected_category:
                logger.error(f"Category '{args.category}' not found")
                print(f"\n❌ Category '{args.category}' not found!")
                print("\nAvailable categories:")
                display_categories(categories)
                return 1
        else:
            # Interactive category selection
            print("\n📋 No category specified. Please select from available categories:")
            display_categories(categories)
            selected_category = select_category(categories)
            
            if not selected_category:
                print("👋 Operation cancelled.")
                return 0
        
        logger.info(f"Selected category: {selected_category.get('configuredName')} (ID: {selected_category.get('id')})")
        
        # Get detailed category information including current URLs
        category_details = uploader.get_category_details(selected_category['id'])
        
        if not category_details:
            logger.error("Failed to fetch category details")
            return 1
        
        # Display detailed category information
        display_category_details(category_details, selected_category)
        
        # Choose which URL list to add to
        url_list_type = choose_url_list_type()
        logger.info(f"Selected URL list type: {url_list_type}")
        
        existing_urls = category_details.get(url_list_type, [])
        logger.info(f"Category {url_list_type} list currently has {len(existing_urls)} URLs")
        print(f"\n📊 Selected list ({url_list_type}) currently has {len(existing_urls)} URLs")
        
        # Handle duplicates in both URL lists comprehensively
        urls_to_upload = handle_all_duplicates(urls_to_upload, category_details, selected_category, url_list_type, logger)
        
        if not urls_to_upload:
            logger.info("No new URLs to upload after removing duplicates.")
            print("ℹ️  No new URLs to upload after removing duplicates.")
            return 0
        
        print(f"\n📤 Ready to upload {len(urls_to_upload)} URLs to '{selected_category.get('configuredName')}' ({url_list_type} list)")
        
        # Final confirmation (skip in non-interactive mode if category was specified)
        if not args.category or input("\nProceed with upload? (y/n): ").strip().lower() in ['y', 'yes']:
            logger.info(f"Starting upload of {len(urls_to_upload)} URLs to {url_list_type} list")
            
            # FIXED: Upload URLs with category name and specified list type
            if uploader.add_urls_to_category(selected_category['id'], urls_to_upload, selected_category.get('configuredName'), url_list_type):
                logger.info("URLs uploaded successfully")
                
                # Activate changes
                if uploader.activate_changes():
                    print("\n🎉 Bulk URL upload completed successfully!")
                    print(f"✅ Added {len(urls_to_upload)} URLs to '{selected_category.get('configuredName')}' ({url_list_type} list)")
                    logger.info(f"Successfully uploaded {len(urls_to_upload)} URLs to category {selected_category['id']} ({url_list_type} list)")
                else:
                    print("\n⚠️  URLs uploaded but activation failed. Please activate manually in the Zscaler portal.")
                    logger.warning("Configuration activation failed")
                    return 1
            else:
                print("\n❌ Upload failed!")
                logger.error("URL upload failed")
                return 1
        else:
            print("👋 Operation cancelled.")
            logger.info("Upload cancelled by user")
            return 0
        
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
            
