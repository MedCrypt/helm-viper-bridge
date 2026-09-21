#!/usr/bin/env python3
"""
Test script for Helm get SBOM API endpoint.
"""

import requests
import json
import sys


def test_get_sbom_by_device_group_id():
    """Test getting SBOM by device group ID."""
    # Load API key
    try:
        with open('api_keys.txt', 'r') as f:
            api_key = f.read().strip().split('\n')[0].split('#')[0].strip()
    except FileNotFoundError:
        print("✗ Error: api_keys.txt not found")
        return 1

    url = 'http://localhost:8000/api/helm-get-sbom'
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }

    # Test data - using first Viper device group example
    data = {
        'device_group_id': 'cxxxxxxxxxxxxxxxxxxxxxxxx'
    }

    print("=" * 70)
    print("Testing Helm Get SBOM API Endpoint (by Device Group ID)")
    print("=" * 70)
    print(f"\nURL: {url}")
    print(f"\nRequest:")
    print(f"  Device Group ID: {data['device_group_id']}")
    print("\nSending request...")

    try:
        response = requests.post(url, headers=headers, json=data, timeout=60)

        print(f"\nResponse Status: {response.status_code}")

        if response.status_code == 200:
            result = response.json()
            print("\n✓ Success! SBOM found and retrieved")

            print(f"\nProduct: {result.get('product_name')}")
            print(f"Version: {result.get('version')}")
            print(f"Product UUID: {result.get('product_uuid')}")
            print(f"Version UUID: {result.get('product_version_uuid')}")

            sbom = result.get('sbom', {})
            print(f"\nSBOM Info:")
            print(f"  Format: {sbom.get('bomFormat', 'N/A')}")
            print(f"  Spec Version: {sbom.get('specVersion', 'N/A')}")

            components = sbom.get('components', [])
            print(f"  Components: {len(components)}")

            vulns = sbom.get('vulnerabilities', [])
            print(f"  Vulnerabilities: {len(vulns)}")

            if len(vulns) > 0:
                print(f"\n  Sample vulnerabilities:")
                for v in vulns[:3]:
                    vuln_id = v.get('id', 'N/A')
                    severity = v.get('ratings', [{}])[0].get('severity', 'N/A') if v.get('ratings') else 'N/A'
                    print(f"    - {vuln_id} ({severity})")

            return 0
        elif response.status_code == 404:
            print(f"\n→ No SBOM found")
            print("   (Either not found, not unique, or doesn't exist)")
            return 0
        else:
            print(f"\n✗ Failed!")
            try:
                error_data = response.json()
                print(f"\nError: {error_data.get('error', 'Unknown error')}")
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


def test_get_sbom_by_product_version_uuid():
    """Test getting SBOM by product version UUID."""
    # Load API key
    try:
        with open('api_keys.txt', 'r') as f:
            api_key = f.read().strip().split('\n')[0].split('#')[0].strip()
    except FileNotFoundError:
        print("✗ Error: api_keys.txt not found")
        return 1

    url = 'http://localhost:8000/api/helm-get-sbom'
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }

    # Test data - using the product version UUID we created earlier
    data = {
        'product_version_uuid': '00000000-0000-0000-0000-000000000000'
    }

    print("\n" + "=" * 70)
    print("Testing Helm Get SBOM API Endpoint (by Product Version UUID)")
    print("=" * 70)
    print(f"\nURL: {url}")
    print(f"\nRequest:")
    print(f"  Product Version UUID: {data['product_version_uuid']}")
    print("\nSending request...")

    try:
        response = requests.post(url, headers=headers, json=data, timeout=60)

        print(f"\nResponse Status: {response.status_code}")

        if response.status_code == 200:
            result = response.json()
            print("\n✓ Success! SBOM found and retrieved")

            print(f"\nProduct: {result.get('product_name')}")
            print(f"Version: {result.get('version')}")
            print(f"Product UUID: {result.get('product_uuid')}")
            print(f"Version UUID: {result.get('product_version_uuid')}")

            sbom = result.get('sbom', {})
            print(f"\nSBOM Info:")
            print(f"  Format: {sbom.get('bomFormat', 'N/A')}")
            print(f"  Spec Version: {sbom.get('specVersion', 'N/A')}")

            components = sbom.get('components', [])
            print(f"  Components: {len(components)}")

            vulns = sbom.get('vulnerabilities', [])
            print(f"  Vulnerabilities: {len(vulns)}")

            return 0
        elif response.status_code == 404:
            print(f"\n→ No SBOM found")
            print("   (Either not found, not unique, or doesn't exist)")
            return 0
        else:
            print(f"\n✗ Failed!")
            try:
                error_data = response.json()
                print(f"\nError: {error_data.get('error', 'Unknown error')}")
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


def test_get_sbom_not_found():
    """Test getting SBOM with non-existent identifier."""
    # Load API key
    try:
        with open('api_keys.txt', 'r') as f:
            api_key = f.read().strip().split('\n')[0].split('#')[0].strip()
    except FileNotFoundError:
        print("✗ Error: api_keys.txt not found")
        return 1

    url = 'http://localhost:8000/api/helm-get-sbom'
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }

    # Test data - using a fake device group ID
    data = {
        'device_group_id': 'nonexistent_device_group_id'
    }

    print("\n" + "=" * 70)
    print("Testing Helm Get SBOM API Endpoint (Not Found Test)")
    print("=" * 70)
    print(f"\nURL: {url}")
    print(f"\nRequest:")
    print(f"  Device Group ID: {data['device_group_id']} (should not exist)")
    print("\nSending request...")

    try:
        response = requests.post(url, headers=headers, json=data, timeout=60)

        print(f"\nResponse Status: {response.status_code}")

        if response.status_code == 404:
            print("\n✓ Correctly returned 404 for non-existent identifier")
            return 0
        else:
            print(f"\n✗ Expected 404 but got {response.status_code}")
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
    results = []

    # Test 1: Get by device group ID
    results.append(test_get_sbom_by_device_group_id())

    # Test 2: Get by product version UUID
    results.append(test_get_sbom_by_product_version_uuid())

    # Test 3: Not found test
    results.append(test_get_sbom_not_found())

    print("\n" + "=" * 70)
    print("All Tests Complete!")
    print("=" * 70)

    passed = sum(1 for r in results if r == 0)
    failed = sum(1 for r in results if r != 0)

    print(f"\nResults: {passed} passed, {failed} failed")

    return 0 if all(r == 0 for r in results) else 1


if __name__ == '__main__':
    sys.exit(main())
