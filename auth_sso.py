#!/usr/bin/env python3
"""
OAuth SSO authentication for self-serve API key generation.
"""

import os
import secrets
from typing import Optional, Dict
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware

from config import (
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    OAUTH_REDIRECT_URI,
    SESSION_SECRET_KEY,
    WHITELISTED_EMAILS_FILE,
    INTERNAL_EMAIL_DOMAINS,
    API_KEYS_FILE,
    EXTERNAL_API_KEYS_FILE,
    VIPER_APP_KEY_FILE
)


# Initialize OAuth
oauth = OAuth()

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={
            'scope': 'openid email profile'
        }
    )


def load_whitelisted_emails():
    """Load whitelisted emails from file."""
    if not os.path.exists(WHITELISTED_EMAILS_FILE):
        return set()

    emails = set()
    with open(WHITELISTED_EMAILS_FILE, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                emails.add(line.lower())
    return emails


def is_internal_email(email: str) -> bool:
    """Check if email domain is internal."""
    domain = email.split('@')[1].lower() if '@' in email else ''
    return domain in INTERNAL_EMAIL_DOMAINS


def is_email_whitelisted(email: str) -> bool:
    """Check if email is whitelisted or from internal domain."""
    email = email.lower()

    # Check if internal domain
    if is_internal_email(email):
        return True

    # Check whitelist
    whitelist = load_whitelisted_emails()
    return email in whitelist


def generate_api_key() -> str:
    """Generate a secure API key."""
    return secrets.token_urlsafe(32)


def save_api_key(email: str, api_key: str, is_internal: bool) -> None:
    """Save API key to appropriate file."""
    filename = API_KEYS_FILE if is_internal else EXTERNAL_API_KEYS_FILE

    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    comment = f"  # {email} | {timestamp} | SSO\n"

    with open(filename, 'a') as f:
        f.write(api_key + comment)


def get_or_create_api_key(email: str, force_regenerate: bool = False) -> Dict[str, any]:
    """
    Get existing API key for email or create new one.

    Args:
        email: User email address
        force_regenerate: If True, invalidate old key and generate new one

    Returns:
        Dict with success, api_key, is_internal, is_new
    """
    email = email.lower()

    # Check if whitelisted
    if not is_email_whitelisted(email):
        return {
            'success': False,
            'error': 'Email not whitelisted',
            'api_key': None,
            'is_internal': False,
            'is_new': False
        }

    is_internal = is_internal_email(email)
    filename = API_KEYS_FILE if is_internal else EXTERNAL_API_KEYS_FILE

    # If regenerate requested, remove old key
    if force_regenerate and os.path.exists(filename):
        with open(filename, 'r') as f:
            lines = f.readlines()

        # Write back all lines except the one with this email
        with open(filename, 'w') as f:
            for line in lines:
                if f'# {email}' not in line.lower():
                    f.write(line)

    # Check if key already exists (and not regenerating)
    if not force_regenerate and os.path.exists(filename):
        with open(filename, 'r') as f:
            for line in f:
                if f'# {email}' in line.lower():
                    # Extract key (first part before #)
                    existing_key = line.split('#')[0].strip()
                    return {
                        'success': True,
                        'api_key': existing_key,
                        'is_internal': is_internal,
                        'is_new': False
                    }

    # Generate new key
    api_key = generate_api_key()
    save_api_key(email, api_key, is_internal)

    return {
        'success': True,
        'api_key': api_key,
        'is_internal': is_internal,
        'is_new': True
    }


def get_viper_app_key() -> Optional[str]:
    """
    Get the current Viper application API key.

    Returns:
        API key string or None if not set
    """
    if not os.path.exists(VIPER_APP_KEY_FILE):
        return None

    with open(VIPER_APP_KEY_FILE, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                return line
    return None


def regenerate_viper_app_key(regenerated_by: str) -> str:
    """
    Regenerate the Viper application API key.

    Args:
        regenerated_by: Email of user who regenerated the key

    Returns:
        New API key
    """
    from datetime import datetime

    # Generate new key
    new_key = generate_api_key()

    # Write to file
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(VIPER_APP_KEY_FILE, 'w') as f:
        f.write(f"# Viper Application API Key\n")
        f.write(f"# Regenerated by: {regenerated_by} on {timestamp}\n")
        f.write(f"{new_key}\n")

    return new_key


def ensure_viper_app_key_exists() -> str:
    """
    Ensure Viper app key exists, create if needed.

    Returns:
        Viper app API key
    """
    existing_key = get_viper_app_key()
    if existing_key:
        return existing_key

    # Generate initial key
    return regenerate_viper_app_key("system")
