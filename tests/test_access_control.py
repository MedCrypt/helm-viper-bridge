#!/usr/bin/env python3
"""
Test script to verify API access control for internal vs external keys.
"""

import requests
import sys


def load_keys():
    """Load internal and external API keys."""
    internal_key = None
    external_key = None

    try:
        with open('api_keys.txt', 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    key = line.split('#')[0].strip()
                    if key:
                        internal_key = key
                        break
    except FileNotFoundError:
        pass

    try:
        with open('external_api_keys.txt', 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    key = line.split('#')[0].strip()
                    if key:
                        external_key = key
                        break
    except FileNotFoundError:
        pass

    return internal_key, external_key


def test_endpoint(url, key, key_type):
    """Test an endpoint with a given key."""
    headers = {
        'Authorization': f'Bearer {key}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(url, headers=headers, json={}, timeout=5)
        return response.status_code, response.json() if response.text else {}
    except Exception as e:
        return None, str(e)


def main():
    """Run access control tests."""
    internal_key, external_key = load_keys()

    if not internal_key:
        print("✗ No internal API key found in api_keys.txt")
        return 1

    if not external_key:
        print("✗ No external API key found in external_api_keys.txt")
        return 1

    base_url = "http://localhost:8000"

    # Define test cases
    # (endpoint, should_work_with_external, description)
    test_cases = [
        ('/api/helm-get-sbom', True, 'Get SBOM (External - Read Only)'),
        ('/api/helm-upload-sbom', False, 'Upload SBOM (Internal)'),
        ('/api/test', False, 'Test endpoint (Internal)'),
        ('/api/helm-create-product', False, 'Create Product (Internal)'),
        ('/api/viper-device-groups', False, 'Viper Device Groups (Internal)'),
    ]

    print("=" * 70)
    print("Testing API Access Control")
    print("=" * 70)
    print()

    results = {'passed': 0, 'failed': 0}

    for endpoint, should_work_with_external, description in test_cases:
        url = base_url + endpoint

        # Test with internal key (should always work)
        print(f"Testing: {description}")
        print(f"  Endpoint: {endpoint}")

        status, response = test_endpoint(url, internal_key, 'internal')
        if status and status not in [400, 404]:  # 400/404 means auth passed but request invalid
            print(f"  ✓ Internal key: Authenticated (HTTP {status})")
            results['passed'] += 1
        else:
            print(f"  ✗ Internal key: Failed (HTTP {status})")
            results['failed'] += 1

        # Test with external key
        status, response = test_endpoint(url, external_key, 'external')

        if should_work_with_external:
            # Should be able to access
            if status and status not in [401, 403]:
                print(f"  ✓ External key: Authenticated (HTTP {status}) - Correct!")
                results['passed'] += 1
            else:
                print(f"  ✗ External key: Denied (HTTP {status}) - WRONG! Should allow access")
                if isinstance(response, dict):
                    print(f"      Error: {response.get('error', 'Unknown')}")
                results['failed'] += 1
        else:
            # Should be denied
            if status in [403]:
                print(f"  ✓ External key: Denied (HTTP {status}) - Correct!")
                results['passed'] += 1
            elif status == 401:
                print(f"  ✗ External key: Auth failed (HTTP {status}) - Should be 403")
                results['failed'] += 1
            else:
                print(f"  ✗ External key: Allowed (HTTP {status}) - WRONG! Should deny access")
                results['failed'] += 1

        print()

    print("=" * 70)
    print("Test Results")
    print("=" * 70)
    print(f"Passed: {results['passed']}")
    print(f"Failed: {results['failed']}")
    print()

    if results['failed'] == 0:
        print("✓ All access control tests passed!")
        return 0
    else:
        print("✗ Some access control tests failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
