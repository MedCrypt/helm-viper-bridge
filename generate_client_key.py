#!/usr/bin/env python3
"""
Generate API key for a client and print to console.
You can then manually encrypt it with their GPG public key.
"""

import secrets
import sys
from datetime import datetime


def generate_api_key():
    """Generate a secure random API key."""
    return secrets.token_urlsafe(32)


def main():
    """Generate key, print to console, and optionally save."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Generate API key for client',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate internal key (full access) and print to console
  %(prog)s --email admin@yourorg.com

  # Generate internal key and save to api_keys.txt
  %(prog)s --email admin@yourorg.com --save

  # Generate external key (SBOM download only, read-only) and save to external_api_keys.txt
  %(prog)s --email partner@external.com --external --save

  # Then encrypt manually with GPG:
  echo "API_KEY" | gpg --encrypt --armor --recipient client@example.com > api_key.asc

  # Send api_key.asc to client
  # Client decrypts: gpg -d api_key.asc
"""
    )

    parser.add_argument('--email',
                       help='Client email/identifier (optional, for tracking only)')
    parser.add_argument('--save', action='store_true',
                       help='Save to api_keys.txt (otherwise just print)')
    parser.add_argument('--external', action='store_true',
                       help='Create external key (limited to SBOM upload/download only)')

    args = parser.parse_args()

    # Generate key
    api_key = generate_api_key()

    print("=" * 70)
    if args.email:
        print(f"API Key for: {args.email}")
    else:
        print("Generated API Key")
    if args.external:
        print("Type: EXTERNAL (Read-Only Access)")
        print("  Can access: /api/helm-get-sbom (download SBOM only)")
    else:
        print("Type: INTERNAL (Full Access)")
        print("  Can access: All endpoints")
    print("=" * 70)
    print()
    print(api_key)
    print()
    print("=" * 70)

    if args.save:
        created_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        key_file = 'external_api_keys.txt' if args.external else 'api_keys.txt'

        with open(key_file, 'a') as f:
            if args.email:
                f.write(f"{api_key}  # {args.email} | {created_date}\n")
            else:
                f.write(f"{api_key}  # Created: {created_date}\n")

        print(f"✓ Added to {key_file}")
        print(f"  Type: {'External (Limited)' if args.external else 'Internal (Full)'}")
        print(f"  Created: {created_date}")
        if args.email:
            print(f"  For: {args.email}")
        print()

    if args.email:
        print("Encrypt with GPG:")
        print(f"  echo '{api_key}' | gpg --encrypt --armor --recipient {args.email} > api_key.asc")
        print()
        print("Send encrypted file to client.")
        print(f"Client decrypts with: gpg -d api_key.asc")
    else:
        print("Encrypt with GPG:")
        print(f"  echo '{api_key}' | gpg --encrypt --armor --recipient CLIENT_EMAIL > api_key.asc")
    print()

    return 0


if __name__ == '__main__':
    sys.exit(main())
