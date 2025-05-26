# Authentication Setup Guide

This guide covers setting up secure authentication for the Zscaler Bulk URL Uploader.

## Authentication Methods

The tool supports two authentication methods:

1. **Certificate-Based Authentication** (🔒 **Recommended** - Most Secure)
2. **Client Secret Authentication** (⚠️ Less Secure)

## Certificate-Based Authentication

### Why Certificate Authentication?

- ✅ **Private keys never leave your environment**
- ✅ **Each user can have unique credentials**
- ✅ **No shared secrets between team members**
- ✅ **Cryptographic proof of identity**
- ✅ **Industry standard for enterprise authentication**
- ✅ **Non-repudiation capabilities**

### Step-by-Step Setup

#### 1. Generate Private Key and Certificate

**Option A: Using the included script (Recommended)**
```bash
# Make script executable
chmod +x examples/generate_keys.sh

# Generate certificates with defaults
./examples/generate_keys.sh

# Generate with custom options
./examples/generate_keys.sh --key-size 4096 --days 730
```

**Option B: Manual generation with OpenSSL**
```bash
# Generate 2048-bit private key
openssl genrsa -out private_key.pem 2048

# Generate certificate signing request (CSR)
openssl req -new -key private_key.pem -out cert.csr \
    -subj "/C=US/ST=State/L=City/O=YourOrganization/CN=zscaler-api-client"

# Generate self-signed certificate (valid for 1 year)
openssl x509 -req -days 365 -in cert.csr -signkey private_key.pem -out certificate.pem

# Clean up CSR file
rm cert.csr

# Set secure permissions
chmod 600 private_key.pem
```

**Option C: Generate password-protected private key**
```bash
# Generate encrypted private key
openssl genrsa -aes256 -out private_key_encrypted.pem 2048

# Generate certificate
openssl req -new -x509 -key private_key_encrypted.pem -out certificate.pem -days 365
```

#### 2. Configure Zscaler ZIdentity

1. **Access ZIdentity Admin Portal**
   - Log in to your ZIdentity Admin Portal
   - Navigate to **Integration** > **API Clients**

2. **Create or Edit API Client**
   - Click **Add API Client** or edit existing client
   - Fill in basic information:
     - **Name**: `Bulk URL Uploader`
     - **Description**: `Automated URL category management`

3. **Configure Authentication**
   - In the **Authentication** section
   - Select **Certificates/Public Keys**
   - Click **Upload Certificate**
   - Upload your `certificate.pem` file

4. **Assign Resources and Scopes**
   - Go to the **Resources** tab
   - Find **ZIA [YOUR-ORG] - INTERNAL**
   - Assign appropriate scopes:
     - `zs:config:deception:[domain]:config:2:Administrator` (for full access)
     - Or more restrictive scopes based on your needs

5. **Save Configuration**
   - Click **Save** to create/update the API client
   - Note down the **Client ID** for configuration

#### 3. Configure the Application

**Option A: Using configuration file**
```yaml
# config.yaml
zscaler:
  vanity_domain: "your-company"           # Without .zslogin.net
  client_id: "your-client-id-from-zidentity"
  private_key_path: "./private_key.pem"
  private_key_password: ""                # Leave empty if not encrypted
```

**Option B: Using environment variables**
```bash
export ZSCALER_VANITY_DOMAIN="your-company"
export ZSCALER_CLIENT_ID="your-client-id"
export ZSCALER_PRIVATE_KEY_PATH="./private_key.pem"
export ZSCALER_PRIVATE_KEY_PASSWORD=""  # Optional
```

#### 4. Test Authentication

```bash
# Test with dry run
python zscaler_bulk_uploader.py --csv examples/sample_urls.csv --dry-run --verbose

# Should show successful authentication message
```

### Certificate Management Best Practices

#### Secure Storage
```bash
# Set restrictive permissions
chmod 600 private_key.pem
chmod 644 certificate.pem

# Move to secure location
mkdir -p ~/.zscaler/keys
mv private_key.pem ~/.zscaler/keys/
mv certificate.pem ~/.zscaler/keys/

# Update configuration
private_key_path: "~/.zscaler/keys/private_key.pem"
```

#### Key Rotation
```bash
# Generate new key pair
./examples/generate_keys.sh --key-file new_private_key.pem --cert-file new_certificate.pem

# Upload new certificate to ZIdentity
# Test with new certificate
# Replace old certificate
# Remove old key files securely
shred -vfz -n 3 old_private_key.pem
```

#### Multiple Environments
```bash
# Development
./examples/generate_keys.sh --key-file dev_private_key.pem --cert-file dev_certificate.pem

# Production  
./examples/generate_keys.sh --key-file prod_private_key.pem --cert-file prod_certificate.pem

# Use different config files
python zscaler_bulk_uploader.py --config dev_config.yaml --csv urls.csv
python zscaler_bulk_uploader.py --config prod_config.yaml --csv urls.csv
```

## Client Secret Authentication

⚠️ **Warning**: Client secrets are less secure and should only be used when certificate authentication is not feasible.

### Setup Steps

#### 1. Configure ZIdentity

1. **Access ZIdentity Admin Portal**
   - Navigate to **Integration** > **API Clients**

2. **Create/Edit API Client**
   - Select **Secret** authentication method
   - Generate or enter a client secret
   - **Important**: Copy the secret immediately - it's only shown once

3. **Assign Resources**
   - Same as certificate method above

#### 2. Configure Application

```yaml
# config.yaml
zscaler:
  vanity_domain: "your-company"
  client_id: "your-client-id"
  client_secret: "your-client-secret"
```

### Client Secret Security

- 🔒 **Store securely**: Use environment variables or encrypted storage
- 🔄 **Rotate regularly**: Change secrets every 90 days
- 📝 **Limit access**: Only authorized personnel should have access
- 🚫 **Never commit**: Don't store secrets in version control

## Troubleshooting Authentication

### Common Issues

#### 1. Authentication Failed (401)
```
❌ Authentication failed: 401
Response: {"detail": "unauthorized"}
```

**Solutions:**
- Verify Client ID is correct
- Check if certificate is uploaded to ZIdentity
- Ensure private key matches uploaded certificate
- Verify vanity domain is correct (without .zslogin.net)

#### 2. No ZIA Resources Available
```
❌ No custom URL categories found!
❌ Failed to fetch categories: 401
```

**Solutions:**
- Check ZIdentity Admin Portal → API Clients → Resources tab
- Ensure ZIA scopes are assigned to your API client
- Verify your organization has ZIA API access enabled
- Contact Zscaler support if no ZIA resources appear

#### 3. Certificate Loading Errors
```
❌ Failed to load private key: [Errno 2] No such file or directory
```

**Solutions:**
- Verify file path is correct
- Check file permissions (should be 600 for private key)
- Ensure file exists and is readable
- Use absolute paths to avoid confusion

#### 4. Private Key Password Issues
```
❌ Failed to load private key: Bad decrypt. Incorrect password?
```

**Solutions:**
- Check if private key is password-protected
- Verify password is correct
- Try with empty password if key is not encrypted

### Debug Authentication

Enable verbose logging:
```bash
python zscaler_bulk_uploader.py --verbose --dry-run --csv examples/sample_urls.csv
```

Check log files:
```bash
tail -f zscaler_uploader.log
```

Test certificate manually:
```bash
# Verify certificate
openssl x509 -in certificate.pem -text -noout

# Check private key
openssl rsa -in private_key.pem -check

# Verify key and certificate match
openssl x509 -noout -modulus -in certificate.pem | openssl md5
openssl rsa -noout -modulus -in private_key.pem | openssl md5
# The MD5 hashes should match
```

## Security Best Practices

### For Certificate Authentication
- ✅ Use 2048-bit or higher RSA keys
- ✅ Set certificate validity to 1 year maximum
- ✅ Store private keys with 600 permissions
- ✅ Use different certificates for different environments
- ✅ Implement key rotation procedures
- ✅ Monitor certificate expiry dates

### For Client Secret Authentication
- ✅ Use strong, randomly generated secrets
- ✅ Store secrets in environment variables or secure vaults
- ✅ Rotate secrets every 90 days
- ✅ Limit secret access to authorized personnel only
- ✅ Never log or display secrets in plaintext
- ✅ Use HTTPS for all API communications

### General Security
- 🔒 **Principle of Least Privilege**: Only assign necessary API scopes
- 🔄 **Regular Audits**: Review API client access regularly  
- 📝 **Audit Logging**: Monitor API usage in Zscaler logs
- 🚫 **No Shared Credentials**: Each user/system should have unique credentials
- 💻 **Secure Workstations**: Ensure development machines are secure

## Advanced Configuration

### Multiple API Clients
```yaml
# For different environments or use cases
development:
  zscaler:
    vanity_domain: "dev-company"
    client_id: "dev-client-id"
    private_key_path: "./keys/dev_private_key.pem"

production:
  zscaler:
    vanity_domain: "company"
    client_id: "prod-client-id" 
    private_key_path: "./keys/prod_private_key.pem"
```

### Automated Key Management
```bash
#!/bin/bash
# Certificate renewal script
EXPIRY_DATE=$(openssl x509 -enddate -noout -in certificate.pem | cut -d= -f 2)
EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s)
CURRENT_EPOCH=$(date +%s)
DAYS_LEFT=$(( ($EXPIRY_EPOCH - $CURRENT_EPOCH) / 86400 ))

if [ $DAYS_LEFT -lt 30 ]; then
    echo "Certificate expires in $DAYS_LEFT days - renewing..."
    ./examples/generate_keys.sh
    # Upload new certificate to ZIdentity
    # Test new certificate
fi
```

## Next Steps

After authentication setup:
1. **Test Connection** - Run a dry-run to verify authentication
2. **Configure Application** - Set up your configuration file
3. **Prepare CSV Files** - Format your URL lists
4. **Start Uploading** - Begin bulk URL operations

## Getting Help

- 🔧 [Configuration Guide](configuration.md)
- 🐛 [Troubleshooting Guide](troubleshooting.md)
- 💬 [Community Discussions](https://github.com/dunwright/zscaler-bulk-url-uploader/discussions)
- 📧 [Contact Support](mailto:your-email@example.com)
