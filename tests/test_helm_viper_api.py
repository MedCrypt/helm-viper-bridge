#!/usr/bin/env python3
"""
Test script for Helm <-> Viper integration API endpoint.
"""

import requests
import json
import base64
import sys

def test_helm_viper_api(
    server_url="http://localhost:8000",
    api_key=None,
    sbom_file=None,
    product_name="Test Product",
    version="1.0.0",
    device_group_id=None,
    helm_sbom_id=None
):
    """Test the /api/helm-viper-sync endpoint."""

    if not api_key:
        print("Error: API key required")
        print("Usage: python3 test_helm_viper_api.py --api-key YOUR_KEY ...")
        return False

    if not device_group_id:
        print("Error: device_group_id required")
        return False

    # Build request payload
    payload = {
        'product_name': product_name,
        'version': version,
        'device_group_id': device_group_id
    }

    # Add SBOM source
    if helm_sbom_id:
        payload['helm_sbom_id'] = helm_sbom_id
        print(f"Using existing Helm SBOM ID: {helm_sbom_id}")
    elif sbom_file:
        try:
            with open(sbom_file, 'rb') as f:
                sbom_b64 = base64.b64encode(f.read()).decode()
            payload['sbom_content'] = sbom_b64
            print(f"Loaded SBOM file: {sbom_file}")
        except FileNotFoundError:
            print(f"Error: SBOM file not found: {sbom_file}")
            return False
    else:
        print("Error: Either --sbom-file or --helm-sbom-id required")
        return False

    # Make API request
    url = f"{server_url}/api/helm-viper-sync"

    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }

    print("\n" + "=" * 70)
    print("Testing Helm <-> Viper API Endpoint")
    print("=" * 70)
    print(f"URL: {url}")
    print(f"Product: {product_name}")
    print(f"Version: {version}")
    print(f"Device Group: {device_group_id}")
    print("=" * 70)

    try:
        print("\nSending request...")
        response = requests.post(url, json=payload, headers=headers, timeout=120)

        print(f"\nStatus Code: {response.status_code}")
        print("\nResponse:")
        print(json.dumps(response.json(), indent=2))

        return response.status_code == 200

    except requests.Timeout:
        print("\n✗ Request timed out")
        return False
    except requests.ConnectionError:
        print(f"\n✗ Could not connect to server at {server_url}")
        print("Make sure the server is running: python3 secure_server.py")
        return False
    except Exception as e:
        print(f"\n✗ Error: {e}")
        return False


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='Test Helm <-> Viper API integration endpoint'
    )

    parser.add_argument('--server-url', default='http://localhost:8000',
                       help='Server URL (default: http://localhost:8000)')
    parser.add_argument('--api-key', required=True,
                       help='API key for authentication')
    parser.add_argument('--sbom-file',
                       help='Path to SBOM file')
    parser.add_argument('--product', default='Test Product',
                       help='Product name (default: Test Product)')
    parser.add_argument('--version', default='1.0.0',
                       help='Version (default: 1.0.0)')
    parser.add_argument('--device-group-id', required=True,
                       help='Viper device group ID')
    parser.add_argument('--helm-sbom-id',
                       help='Existing Helm product version UUID (skip upload)')

    args = parser.parse_args()

    success = test_helm_viper_api(
        server_url=args.server_url,
        api_key=args.api_key,
        sbom_file=args.sbom_file,
        product_name=args.product,
        version=args.version,
        device_group_id=args.device_group_id,
        helm_sbom_id=args.helm_sbom_id
    )

    sys.exit(0 if success else 1)
