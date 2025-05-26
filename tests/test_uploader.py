#!/usr/bin/env python3
"""
Unit tests for Zscaler Bulk URL Uploader
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Import the main module
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from zscaler_bulk_uploader import (
    ZscalerURLUploader,
    clean_url,
    validate_url,
    parse_csv_file,
    load_config,
    ZscalerError,
    AuthenticationError,
    APIError,
    ConfigurationError
)


class TestURLCleaning:
    """Test URL cleaning functionality"""
    
    def test_clean_url_http(self):
        """Test cleaning HTTP URLs"""
        assert clean_url("http://example.com") == "example.com"
        assert clean_url("HTTP://EXAMPLE.COM") == "EXAMPLE.COM"
    
    def test_clean_url_https(self):
        """Test cleaning HTTPS URLs"""
        assert clean_url("https://example.com") == "example.com"
        assert clean_url("HTTPS://EXAMPLE.COM") == "EXAMPLE.COM"
    
    def test_clean_url_no_prefix(self):
        """Test URLs without prefixes"""
        assert clean_url("example.com") == "example.com"
        assert clean_url("  example.com  ") == "example.com"
    
    def test_clean_url_empty(self):
        """Test empty URLs"""
        assert clean_url("") == ""
        assert clean_url("   ") == ""
        assert clean_url(None) == ""


class TestURLValidation:
    """Test URL validation functionality"""
    
    def test_validate_url_valid(self):
        """Test valid URLs"""
        assert validate_url("example.com") == True
        assert validate_url("subdomain.example.com") == True
        assert validate_url("example.co.uk") == True
    
    def test_validate_url_invalid(self):
        """Test invalid URLs"""
        assert validate_url("") == False
        assert validate_url("   ") == False
        assert validate_url("no-dots") == False
        assert validate_url("example<.com") == False
        assert validate_url("example>.com") == False
    
    def test_validate_url_edge_cases(self):
        """Test edge cases"""
        assert validate_url("a.b") == True  # Minimal valid URL
        assert validate_url("192.168.1.1") == True  # IP address


class TestCSVParsing:
    """Test CSV file parsing"""
    
    def test_parse_csv_simple(self):
        """Test parsing simple CSV"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("URL\nexample.com\nhttps://test.com\n")
            csv_path = f.name
        
        try:
            logger = Mock()
            urls = parse_csv_file(csv_path, logger)
            assert len(urls) == 2
            assert "example.com" in urls
            assert "test.com" in urls
        finally:
            os.unlink(csv_path)
    
    def test_parse_csv_multiple_columns(self):
        """Test parsing CSV with multiple columns"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("Name,URL,Category\nExample,example.com,Test\nTest,https://test.com,Dev\n")
            csv_path = f.name
        
        try:
            logger = Mock()
            urls = parse_csv_file(csv_path, logger)
            assert len(urls) == 2
            assert "example.com" in urls
            assert "test.com" in urls
        finally:
            os.unlink(csv_path)
    
    def test_parse_csv_duplicates(self):
        """Test parsing CSV with duplicates"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("URL\nexample.com\nEXAMPLE.COM\nhttps://example.com\n")
            csv_path = f.name
        
        try:
            logger = Mock()
            urls = parse_csv_file(csv_path, logger)
            assert len(urls) == 1  # Duplicates removed
            assert urls[0] == "example.com"
        finally:
            os.unlink(csv_path)
    
    def test_parse_csv_file_not_found(self):
        """Test parsing non-existent CSV file"""
        logger = Mock()
        with pytest.raises(ConfigurationError):
            parse_csv_file("/nonexistent/file.csv", logger)


class TestConfiguration:
    """Test configuration loading"""
    
    def test_load_config_default(self):
        """Test loading default configuration"""
        config = load_config()
        assert 'zscaler' in config
        assert 'upload' in config
        assert 'logging' in config
        assert config['upload']['batch_size'] == 100
    
    def test_load_config_file(self):
        """Test loading configuration from file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
zscaler:
  vanity_domain: "test-company"
  client_id: "test-client"
upload:
  batch_size: 200
""")
            config_path = f.name
        
        try:
            config = load_config(config_path)
            assert config['zscaler']['vanity_domain'] == "test-company"
            assert config['upload']['batch_size'] == 200
        finally:
            os.unlink(config_path)


class TestZscalerUploader:
    """Test ZscalerURLUploader class"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.config = {
            'zscaler': {
                'base_url': 'https://api.zsapi.net/zia/api/v1',
                'token_url_template': 'https://{vanity_domain}.zslogin.net/oauth2/v1/token',
                'audience': 'https://api.zscaler.com'
            },
            'upload': {
                'batch_size': 100,
                'retry_attempts': 3,
                'timeout': 60
            }
        }
        self.logger = Mock()
        self.uploader = ZscalerURLUploader(self.config, self.logger)
    
    def test_initialization(self):
        """Test uploader initialization"""
        assert self.uploader.base_url == self.config['zscaler']['base_url']
        assert self.uploader.access_token is None
        assert 'User-Agent' in self.uploader.session.headers
    
    @patch('zscaler_bulk_uploader.load_pem_private_key')
    @patch('builtins.open')
    def test_load_private_key_success(self, mock_open, mock_load_key):
        """Test successful private key loading"""
        mock_key = Mock()
        mock_load_key.return_value = mock_key
        mock_open.return_value.__enter__.return_value.read.return_value = b'key-data'
        
        result = self.uploader.load_private_key('test.pem')
        assert result == mock_key
    
    def test_load_private_key_file_not_found(self):
        """Test private key loading with missing file"""
        with pytest.raises(AuthenticationError):
            self.uploader.load_private_key('/nonexistent/key.pem')
    
    @patch('zscaler_bulk_uploader.jwt.encode')
    def test_create_jwt_assertion(self, mock_jwt_encode):
        """Test JWT assertion creation"""
        mock_jwt_encode.return_value = 'test-token'
        private_key = Mock()
        
        token = self.uploader.create_jwt_assertion('client-id', private_key, 'company')
        assert token == 'test-token'
        mock_jwt_encode.assert_called_once()
    
    @patch('requests.Session.post')
    def test_authenticate_with_secret_success(self, mock_post):
        """Test successful client secret authentication"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'access_token': 'test-token',
            'expires_in': 3600
        }
        mock_post.return_value = mock_response
        
        result = self.uploader.authenticate_with_secret('company', 'client-id', 'secret')
        assert result == True
        assert self.uploader.access_token == 'test-token'
    
    @patch('requests.Session.post')
    def test_authenticate_with_secret_failure(self, mock_post):
        """Test failed client secret authentication"""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = 'Unauthorized'
        mock_post.return_value = mock_response
        
        with pytest.raises(AuthenticationError):
            self.uploader.authenticate_with_secret('company', 'client-id', 'wrong-secret')
    
    @patch('requests.Session.request')
    def test_make_request_success(self, mock_request):
        """Test successful API request"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'result': 'success'}
        mock_request.return_value = mock_response
        
        response = self.uploader._make_request('GET', '/test')
        assert response.status_code == 200
    
    @patch('requests.Session.request')
    def test_make_request_retry(self, mock_request):
        """Test API request with retry logic"""
        # First call fails, second succeeds
        mock_response_fail = Mock()
        mock_response_fail.status_code = 500
        mock_response_fail.text = 'Server Error'
        
        mock_response_success = Mock()
        mock_response_success.status_code = 200
        
        mock_request.side_effect = [mock_response_fail, mock_response_success]
        
        with patch('time.sleep'):  # Mock sleep to speed up test
            response = self.uploader._make_request('GET', '/test')
            assert response.status_code == 200
            assert mock_request.call_count == 2
    
    @patch('requests.Session.request')
    def test_make_request_max_retries(self, mock_request):
        """Test API request exceeding max retries"""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = 'Server Error'
        mock_request.return_value = mock_response
        
        with patch('time.sleep'):  # Mock sleep to speed up test
            with pytest.raises(APIError):
                self.uploader._make_request('GET', '/test')
    
    @patch.object(ZscalerURLUploader, '_make_request')
    def test_get_custom_categories(self, mock_make_request):
        """Test getting custom categories"""
        mock_response = Mock()
        mock_response.json.return_value = [
            {'id': 'CUSTOM_01', 'configuredName': 'Test Category'},
            {'id': 'PREDEFINED_01', 'configuredName': ''},  # Should be filtered out
            {'id': 'CUSTOM_02', 'configuredName': 'Another Category'}
        ]
        mock_make_request.return_value = mock_response
        
        categories = self.uploader.get_custom_categories()
        assert len(categories) == 2
        assert categories[0]['configuredName'] == 'Test Category'
    
    @patch.object(ZscalerURLUploader, '_make_request')
    def test_add_urls_to_category(self, mock_make_request):
        """Test adding URLs to category"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_make_request.return_value = mock_response
        
        urls = ['example.com', 'test.com']
        result = self.uploader.add_urls_to_category('CUSTOM_01', urls)
        assert result == True
        mock_make_request.assert_called_once()
    
    @patch.object(ZscalerURLUploader, '_make_request')
    def test_add_urls_batch_processing(self, mock_make_request):
        """Test batch processing for large URL lists"""
        # Set small batch size for testing
        self.uploader.config['upload']['batch_size'] = 2
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_make_request.return_value = mock_response
        
        urls = ['url1.com', 'url2.com', 'url3.com']  # 3 URLs, batch size 2
        result = self.uploader.add_urls_to_category('CUSTOM_01', urls)
        assert result == True
        assert mock_make_request.call_count == 2  # 2 batches
    
    @patch.object(ZscalerURLUploader, '_make_request')
    def test_activate_changes(self, mock_make_request):
        """Test activating configuration changes"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_make_request.return_value = mock_response
        
        result = self.uploader.activate_changes()
        assert result == True
        mock_make_request.assert_called_with('POST', '/status/activate')


class TestExceptions:
    """Test custom exception classes"""
    
    def test_zscaler_error(self):
        """Test base ZscalerError"""
        error = ZscalerError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)
    
    def test_authentication_error(self):
        """Test AuthenticationError"""
        error = AuthenticationError("Auth failed")
        assert str(error) == "Auth failed"
        assert isinstance(error, ZscalerError)
    
    def test_api_error(self):
        """Test APIError"""
        error = APIError("API failed")
        assert str(error) == "API failed"
        assert isinstance(error, ZscalerError)
    
    def test_configuration_error(self):
        """Test ConfigurationError"""
        error = ConfigurationError("Config failed")
        assert str(error) == "Config failed"
        assert isinstance(error, ZscalerError)


class TestIntegration:
    """Integration tests (require mocking external dependencies)"""
    
    @patch('zscaler_bulk_uploader.ZscalerURLUploader')
    def test_full_workflow_mock(self, mock_uploader_class):
        """Test full workflow with mocked uploader"""
        # Set up mock uploader instance
        mock_uploader = Mock()
        mock_uploader.authenticate_with_certificate.return_value = True
        mock_uploader.get_custom_categories.return_value = [
            {'id': 'CUSTOM_01', 'configuredName': 'Test Category'}
        ]
        mock_uploader.get_category_details.return_value = {
            'urls': ['existing.com']
        }
        mock_uploader.add_urls_to_category.return_value = True
        mock_uploader.activate_changes.return_value = True
        mock_uploader_class.return_value = mock_uploader
        
        # This would be part of a full integration test
        # Testing the complete flow from CSV to upload
        assert True  # Placeholder for actual integration test


if __name__ == '__main__':
    # Run tests
    pytest.main([__file__, '-v'])
