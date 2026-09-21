#!/usr/bin/env python3
"""
Test script for Helm create product API endpoint.
"""

import requests
import json
import sys
import base64


def test_create_product_without_sbom():
    """Test creating product and version without SBOM upload."""
    # Load API key
    try:
        with open('api_keys.txt', 'r') as f:
            api_key = f.read().strip().split('\n')[0].split('#')[0].strip()
    except FileNotFoundError:
        print("✗ Error: api_keys.txt not found")
        return 1

    url = 'http://localhost:8000/api/helm-create-product'
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }

    # Test data - using first Viper device group example
    data = {
        'product_name': 'acme:sample-scanner',
        'version': 'cxxxxxxxxxxxxxxxxxxxxxxxx'
        # No SBOM provided for this test
    }

    print("=" * 70)
    print("Testing Helm Create Product API Endpoint")
    print("=" * 70)
    print(f"\nURL: {url}")
    print(f"\nRequest:")
    print(f"  Product: {data['product_name']}")
    print(f"  Version: {data['version']}")
    print(f"  SBOM: None")
    print("\nSending request...")

    try:
        response = requests.post(url, headers=headers, json=data, timeout=60)

        print(f"\nResponse Status: {response.status_code}")

        if response.status_code == 200:
            result = response.json()
            print("\n✓ Success!")

            print(f"\nProduct UUID: {result.get('product_uuid')}")
            print(f"Version UUID: {result.get('product_version_uuid')}")

            if result.get('product_created'):
                print(f"\n✓ Product '{data['product_name']}' was created")
            else:
                print(f"\n→ Product '{data['product_name']}' already existed")

            if result.get('version_created'):
                print(f"✓ Version '{data['version']}' was created")
            else:
                print(f"→ Version '{data['version']}' already existed")

            if result.get('sbom_uploaded'):
                print("✓ SBOM was uploaded")

            print("\nSteps taken:")
            for step in result.get('steps', []):
                print(f"  {step}")

            return 0
        else:
            print(f"\n✗ Failed!")
            try:
                error_data = response.json()
                print(f"\nError: {error_data.get('error', 'Unknown error')}")
                if 'steps' in error_data:
                    print("\nSteps before failure:")
                    for step in error_data['steps']:
                        print(f"  {step}")
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


def test_create_product_with_sbom():
    """Test creating product with SBOM upload (placeholder for future use)."""
    print("\n" + "=" * 70)
    print("Test with SBOM Upload (Optional)")
    print("=" * 70)
    print("\nTo test with SBOM, add 'sbom_content' parameter:")
    print("  data['sbom_content'] = base64.b64encode(sbom_bytes).decode()")
    print("  data['sbom_filename'] = 'sbom.json'")
    print("  data['file_type'] = 'CDX'  # or 'SPDX'")


def main():
    """Main test runner."""
    result = test_create_product_without_sbom()

    print("\n" + "=" * 70)
    print("Test Complete!")
    print("=" * 70)

    # Show optional test info
    test_create_product_with_sbom()

    return result


if __name__ == '__main__':
    sys.exit(main())
