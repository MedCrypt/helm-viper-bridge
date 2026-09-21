#!/usr/bin/env python3
"""
Direct test of Viper API to find correct endpoints.
"""

import requests
import json


def load_viper_key():
    """Load Viper API key."""
    with open('viper_api_key.txt', 'r') as f:
        return f.read().strip()


def test_endpoint(url, method='GET', api_key=None):
    """Test a Viper API endpoint."""
    headers = {
        'Content-Type': 'application/json'
    }

    if api_key:
        headers['Authorization'] = f'Bearer {api_key}'

    print(f"\n{'='*70}")
    print(f"Testing: {method} {url}")
    print(f"{'='*70}")

    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, timeout=10)
        elif method == 'POST':
            response = requests.post(url, headers=headers, json={}, timeout=10)
        else:
            print(f"Unsupported method: {method}")
            return

        print(f"Status: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")

        if response.status_code == 200:
            print("\n✓ Success!")
            try:
                data = response.json()
                print(f"Response: {json.dumps(data, indent=2)}")
            except:
                print(f"Response (text): {response.text[:500]}")
        else:
            print(f"\n✗ Failed")
            print(f"Response: {response.text[:500]}")

    except Exception as e:
        print(f"\n✗ Error: {e}")


def main():
    """Test various Viper API endpoints."""
    api_key = load_viper_key()
    base_url = "https://viper-xi.vercel.app/api"

    print("="*70)
    print("Viper API Endpoint Discovery")
    print("="*70)
    print(f"\nBase URL: {base_url}")
    print(f"API Key: {api_key[:10]}...")

    # Try different possible endpoints
    endpoints_to_try = [
        ('GET', '/devicegroups'),
        ('GET', '/device-groups'),
        ('GET', '/deviceGroups'),
        ('POST', '/devicegroups'),
        ('GET', '/devicegroups/list'),
        ('GET', '/v1/devicegroups'),
    ]

    for method, path in endpoints_to_try:
        test_endpoint(f"{base_url}{path}", method, api_key)

    print("\n" + "="*70)
    print("Test complete!")
    print("="*70)
    print("\nIf you see a 200 response above, that's the correct endpoint!")
    print("Update helm_viper_integration.py with the correct path.")


if __name__ == '__main__':
    main()
