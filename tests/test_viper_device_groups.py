#!/usr/bin/env python3
"""
Test script for listing Viper device groups via API endpoint.
"""

import requests
import json
import sys


def test_list_device_groups():
    """Test the /api/viper-device-groups endpoint."""
    # Load API key
    try:
        with open('api_keys.txt', 'r') as f:
            # Get first line, strip whitespace and any inline comments
            api_key = f.read().strip().split('\n')[0].split('#')[0].strip()
    except FileNotFoundError:
        print("✗ Error: api_keys.txt not found")
        print("  Generate with: python3 generate_api_key.py")
        return 1

    url = 'http://localhost:8000/api/viper-device-groups'
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }

    print("=" * 70)
    print("Testing Viper Device Groups API Endpoint")
    print("=" * 70)
    print(f"\nURL: {url}")
    print("\nSending request...")

    try:
        response = requests.post(url, headers=headers, timeout=30)

        print(f"\nResponse Status: {response.status_code}")

        if response.status_code == 200:
            result = response.json()
            print("\n✓ Success!")

            device_groups = result.get('device_groups', [])
            count = result.get('count', 0)

            print(f"\nTotal Device Groups: {count}")

            if count > 0:
                print("\nDevice Groups:")
                print("-" * 70)
                for i, group in enumerate(device_groups, 1):
                    print(f"\n{i}. {group.get('name', 'Unnamed')}")
                    print(f"   ID: {group.get('id', 'N/A')}")
                    if 'helmSbomId' in group:
                        print(f"   Helm SBOM ID: {group.get('helmSbomId')}")
                    if 'description' in group:
                        print(f"   Description: {group.get('description')}")
                    # Show other fields that might be present
                    for key, value in group.items():
                        if key not in ['name', 'id', 'helmSbomId', 'description']:
                            print(f"   {key}: {value}")
            else:
                print("\n⚠ No device groups found")
                print("  Create device groups in Viper first")

            return 0
        else:
            print(f"\n✗ Failed!")
            try:
                error_data = response.json()
                print(f"Error: {json.dumps(error_data, indent=2)}")
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
    return test_list_device_groups()


if __name__ == '__main__':
    sys.exit(main())
