#!/bin/bash
# 
# Zscaler Certificate Generation Script
# Generates private key and certificate for Zscaler API authentication
#

set -e  # Exit on any error

echo "🔐 Zscaler Certificate Generation Script"
echo "========================================"
echo

# Check if OpenSSL is installed
if ! command -v openssl &> /dev/null; then
    echo "❌ OpenSSL is not installed. Please install OpenSSL first."
    echo "   Ubuntu/Debian: sudo apt install openssl"
    echo "   CentOS/RHEL:   sudo yum install openssl"
    echo "   macOS:         brew install openssl"
    exit 1
fi

# Set default values
KEY_SIZE=2048
DAYS=365
KEY_FILE="private_key.pem"
CERT_FILE="certificate.pem"
SUBJECT="/C=US/ST=State/L=City/O=Organization/CN=zscaler-api-client"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --key-size)
            KEY_SIZE="$2"
            shift 2
            ;;
        --days)
            DAYS="$2"
            shift 2
            ;;
        --key-file)
            KEY_FILE="$2"
            shift 2
            ;;
        --cert-file)
            CERT_FILE="$2"
            shift 2
            ;;
        --subject)
            SUBJECT="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo
            echo "Options:"
            echo "  --key-size SIZE    RSA key size (default: 2048)"
            echo "  --days DAYS        Certificate validity days (default: 365)"
            echo "  --key-file FILE    Private key filename (default: private_key.pem)"
            echo "  --cert-file FILE   Certificate filename (default: certificate.pem)"
            echo "  --subject SUBJECT  Certificate subject (default: auto)"
            echo "  --help, -h         Show this help message"
            echo
            echo "Examples:"
            echo "  $0                                    # Use defaults"
            echo "  $0 --key-size 4096 --days 730       # 4096-bit key, 2-year cert"
            echo
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check if files already exist
if [[ -f "$KEY_FILE" ]]; then
    echo "⚠️  Private key file '$KEY_FILE' already exists!"
    read -p "Overwrite? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Aborted."
        exit 1
    fi
fi

if [[ -f "$CERT_FILE" ]]; then
    echo "⚠️  Certificate file '$CERT_FILE' already exists!"
    read -p "Overwrite? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Aborted."
        exit 1
    fi
fi

echo "📋 Configuration:"
echo "   Key Size:    $KEY_SIZE bits"
echo "   Validity:    $DAYS days"
echo "   Private Key: $KEY_FILE"
echo "   Certificate: $CERT_FILE"
echo "   Subject:     $SUBJECT"
echo

# Generate private key
echo "🔑 Generating private key..."
openssl genrsa -out "$KEY_FILE" "$KEY_SIZE"

if [[ $? -eq 0 ]]; then
    echo "✅ Private key generated: $KEY_FILE"
else
    echo "❌ Failed to generate private key"
    exit 1
fi

# Set secure permissions on private key
chmod 600 "$KEY_FILE"
echo "🔒 Set secure permissions (600) on private key"

# Generate self-signed certificate
echo "📜 Generating certificate..."
openssl req -new -x509 -key "$KEY_FILE" -out "$CERT_FILE" -days "$DAYS" -subj "$SUBJECT"

if [[ $? -eq 0 ]]; then
    echo "✅ Certificate generated: $CERT_FILE"
else
    echo "❌ Failed to generate certificate"
    exit 1
fi

# Display certificate information
echo
echo "📋 Certificate Information:"
echo "=========================="
openssl x509 -in "$CERT_FILE" -text -noout | grep -E "(Subject:|Not Before:|Not After:|Public Key:|Signature Algorithm:)"

echo
echo "🎉 Certificate generation completed successfully!"
echo
echo "📤 Next Steps:"
echo "1. Upload '$CERT_FILE' to Zscaler ZIdentity Admin Portal:"
echo "   - Go to Integration > API Clients"
echo "   - Select your API client"
echo "   - Upload the certificate file in Authentication section"
echo
echo "2. Configure your application to use '$KEY_FILE'"
echo
echo "3. Keep '$KEY_FILE' secure and do not share it!"
echo
echo "⚠️  Security Notes:"
echo "   - The private key file has been set to read-only for owner (600)"
echo "   - Never commit private keys to version control"
echo "   - Store private keys in secure locations (key vaults, HSMs)"
echo "   - Consider using encrypted private keys for additional security"
echo

# Optionally create encrypted private key
read -p "🔐 Create password-protected private key? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    ENCRYPTED_KEY="${KEY_FILE%.pem}_encrypted.pem"
    echo "🔐 Creating encrypted private key..."
    openssl rsa -in "$KEY_FILE" -aes256 -out "$ENCRYPTED_KEY"
    
    if [[ $? -eq 0 ]]; then
        chmod 600 "$ENCRYPTED_KEY"
        echo "✅ Encrypted private key created: $ENCRYPTED_KEY"
        echo "   Use this file if you prefer password-protected keys"
    else
        echo "❌ Failed to create encrypted private key"
    fi
fi

echo
echo "✅ All done! Your certificates are ready for use with Zscaler."
