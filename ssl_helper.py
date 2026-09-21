#!/usr/bin/env python3
"""
SSL certificate helper for Helm API requests.
Finds the correct CA bundle path for SSL verification.
"""

import os
import sys


def get_ca_bundle():
    """
    Get the path to the CA certificate bundle.

    Tries multiple methods to find a valid CA bundle:
    1. certifi package
    2. System CA bundle (macOS)
    3. System CA bundle (Linux)

    Returns:
        str: Path to CA bundle, or True to use default verification
    """
    # Try certifi first
    try:
        import certifi
        ca_path = certifi.where()
        if os.path.exists(ca_path):
            return ca_path
    except (ImportError, Exception):
        pass

    # Try macOS system certificates
    macos_paths = [
        '/etc/ssl/cert.pem',
        '/usr/local/etc/openssl/cert.pem',
        '/usr/local/etc/[email protected]/cert.pem',
        '/System/Library/OpenSSL/cert.pem'
    ]

    for path in macos_paths:
        if os.path.exists(path):
            return path

    # Try Linux system certificates
    linux_paths = [
        '/etc/ssl/certs/ca-certificates.crt',
        '/etc/pki/tls/certs/ca-bundle.crt',
        '/etc/ssl/ca-bundle.pem',
        '/etc/pki/tls/cacert.pem',
        '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'
    ]

    for path in linux_paths:
        if os.path.exists(path):
            return path

    # Fall back to default verification (requests will try to find certificates)
    # This will use the system's default certificate store
    return True


def get_requests_kwargs():
    """
    Get kwargs dict for requests with proper SSL verification.

    Returns:
        dict: Dictionary with 'verify' key set to appropriate value
    """
    return {'verify': get_ca_bundle()}


if __name__ == '__main__':
    # Test the helper
    ca_bundle = get_ca_bundle()
    print(f"CA Bundle: {ca_bundle}")

    if ca_bundle is True:
        print("Using default certificate verification")
    elif os.path.exists(str(ca_bundle)):
        print(f"✓ Certificate bundle found and verified")
    else:
        print(f"⚠ Certificate bundle path returned but file doesn't exist")
