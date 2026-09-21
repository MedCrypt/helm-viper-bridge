"""
Server Configuration File

Copy this file to config.py and fill in your values:
    cp config.example.py config.py

config.py is gitignored — never commit it.
"""

# ============================================================================
# File Locations
# ============================================================================

API_KEYS_FILE          = "api_keys.txt"
EXTERNAL_API_KEYS_FILE = "external_api_keys.txt"
BLOCKED_IPS_FILE       = "blocked_ips.txt"
WHITELISTED_EMAILS_FILE = "whitelisted_emails.txt"
VIPER_APP_KEY_FILE     = "viper_app_key.txt"


# ============================================================================
# OAuth Configuration (Self-Serve API Keys via Google SSO)
# ============================================================================

# From Google Cloud Console → APIs & Services → Credentials
GOOGLE_CLIENT_ID     = "YOUR_CLIENT_ID.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "YOUR_CLIENT_SECRET"

# Must match exactly what is registered in Google Cloud Console
OAUTH_REDIRECT_URI = "https://helm-api.com/auth/callback"

# Generate with: openssl rand -hex 32
SESSION_SECRET_KEY = "CHANGE_ME_generate_with_openssl_rand_hex_32"

# Users with these email domains automatically receive internal (full-access) keys
INTERNAL_EMAIL_DOMAINS = ["medcrypt.com", "medcrypt.co"]


# ============================================================================
# Helm API Configuration
# ============================================================================

# Production:      https://helm.medcrypt.co/api-gw/v1
# Coffee Sandbox:  https://helm.coffee-sandbox.medcrypt.co/api-gw/v1
HELM_API_URL        = "https://helm.coffee-sandbox.medcrypt.co/api-gw/v1"
HELM_WORKSPACE_NAME = "YOUR_WORKSPACE_NAME"
HELM_PRODUCT_NAME   = "YOUR_PRODUCT_NAME"


# ============================================================================
# Request Limits
# ============================================================================

MAX_REQUEST_SIZE = 1024 * 1024  # 1 MB
REQUEST_TIMEOUT  = 10           # seconds


# ============================================================================
# Rate Limiting
# ============================================================================

GLOBAL_RATE_LIMIT_WINDOW        = 60   # seconds
GLOBAL_RATE_LIMIT_MAX_REQUESTS  = 100  # requests per window (all IPs combined)

RATE_LIMIT_WINDOW       = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 60  # requests per window per IP


# ============================================================================
# Connection Limits
# ============================================================================

MAX_CONCURRENT_CONNECTIONS = 50


# ============================================================================
# Server Settings
# ============================================================================

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8000


# ============================================================================
# Security Headers
# ============================================================================

SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
}


# ============================================================================
# Configuration Validation
# ============================================================================

def validate_config():
    errors = []

    if MAX_REQUEST_SIZE < 1024:
        errors.append("MAX_REQUEST_SIZE too small (minimum 1KB)")
    if REQUEST_TIMEOUT < 1:
        errors.append("REQUEST_TIMEOUT must be at least 1 second")
    if GLOBAL_RATE_LIMIT_MAX_REQUESTS < 1:
        errors.append("GLOBAL_RATE_LIMIT_MAX_REQUESTS must be at least 1")
    if RATE_LIMIT_MAX_REQUESTS < 1:
        errors.append("RATE_LIMIT_MAX_REQUESTS must be at least 1")
    if MAX_CONCURRENT_CONNECTIONS < 1:
        errors.append("MAX_CONCURRENT_CONNECTIONS must be at least 1")
    if DEFAULT_PORT < 1 or DEFAULT_PORT > 65535:
        errors.append("DEFAULT_PORT must be between 1 and 65535")
    if not HELM_PRODUCT_NAME or HELM_PRODUCT_NAME == "YOUR_PRODUCT_NAME":
        errors.append("HELM_PRODUCT_NAME must be configured")

    if errors:
        raise ValueError("Configuration errors:\n  - " + "\n  - ".join(errors))

    return True


validate_config()
