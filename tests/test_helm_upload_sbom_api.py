#!/usr/bin/env python3
"""
Test script for Helm upload SBOM API endpoint.
"""

import requests
import json
import sys
import base64


def test_upload_sbom():
    """Test uploading SBOM to product version."""
    # Load API key
    try:
        with open('api_keys.txt', 'r') as f:
            api_key = f.read().strip().split('\n')[0].split('#')[0].strip()
    except FileNotFoundError:
        print("✗ Error: api_keys.txt not found")
        return 1

    # Load SBOM file
    try:
        with open('test_sbom.json', 'rb') as f:
            sbom_bytes = f.read()
    except FileNotFoundError:
        print("✗ Error: test_sbom.json not found")
        return 1

    # Encode SBOM to base64
    sbom_base64 = base64.b64encode(sbom_bytes).decode()

    url = 'http://localhost:8000/api/helm-upload-sbom'
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }

    # Test data - upload to acme:sample-scanner product we created earlier
    data = {
        'product_version_uuid': '00000000-0000-0000-0000-000000000000',
        'sbom_content': sbom_base64,
        'sbom_filename': 'test_sbom.json',
        'file_type': 'CDX'
    }

    print("=" * 70)
    print("Testing Helm Upload SBOM API Endpoint")
    print("=" * 70)
    print(f"\nURL: {url}")
    print(f"\nRequest:")
    print(f"  Product Version UUID: {data['product_version_uuid']}")
    print(f"  SBOM File: test_sbom.json ({len(sbom_bytes)} bytes)")
    print(f"  File Type: {data['file_type']}")
    print("\nSending request...")

    try:
        response = requests.post(url, headers=headers, json=data, timeout=60)

        print(f"\nResponse Status: {response.status_code}")

        if response.status_code == 200:
            result = response.json()
            print("\n✓ Success! SBOM uploaded")

            print(f"\nProduct: {result.get('product_name')}")
            print(f"Version: {result.get('version')}")
            print(f"Product UUID: {result.get('product_uuid')}")
            print(f"Version UUID: {result.get('product_version_uuid')}")
            print(f"File: {result.get('filename')} ({result.get('size')} bytes)")
            print(f"\nMessage: {result.get('message')}")

            return 0
        else:
            print(f"\n✗ Failed!")
            try:
                error_data = response.json()
                print(f"\nError: {error_data.get('error', 'Unknown error')}")
                if 'traceback' in error_data:
                    print(f"\nTraceback:\n{error_data['traceback']}")
            except:
                print(f"Response: {response.text}")
            return 1

    except requests.exceptions.ConnectionError:
        print("\n✗ Connection Error - Is the server running?")
        print("  Start with: python3 secure_server.py")
        return 1
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


def main():
    """Main test runner."""
    result = test_upload_sbom()

    print("\n" + "=" * 70)
    if result == 0:
        print("Test Passed!")
    else:
        print("Test Failed!")
    print("=" * 70)

    return result


if __name__ == '__main__':
    sys.exit(main())
