#!/usr/bin/env python3
"""
Test script for the Helm SBOM export API endpoint.
"""

import requests
import json

def test_export_endpoint():
    """Test the /api/helm-export-sbom endpoint."""
    # Load API key
    with open('api_keys.txt', 'r') as f:
        api_key = f.read().strip()

    url = 'http://localhost:8000/api/helm-export-sbom'
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }

    # Test exporting sample product v1.0
    data = {
        'version': '1.0'
        # product_name and workspace_name will use config defaults
    }

    print("=" * 70)
    print("Testing Helm SBOM Export API Endpoint")
    print("=" * 70)
    print(f"\nURL: {url}")
    print(f"Request: {json.dumps(data, indent=2)}")
    print("\nSending request...")

    try:
        response = requests.post(url, headers=headers, json=data, timeout=120)

        print(f"\nResponse Status: {response.status_code}")

        if response.status_code == 200:
            result = response.json()
            print("\n✓ Success!")
            print(f"\nMessage: {result['message']}")

            metadata = result.get('metadata', {})
            print(f"\nMetadata:")
            print(f"  Product: {metadata.get('product')}")
            print(f"  Version: {metadata.get('version')}")
            print(f"  Workspace: {metadata.get('workspace')}")
            print(f"  Format: {metadata.get('format')}")
            print(f"  Spec Version: {metadata.get('spec_version')}")

            sbom = result.get('sbom', {})
            vulns = sbom.get('vulnerabilities', [])
            components = sbom.get('components', [])

            print(f"\nSBOM Details:")
            print(f"  Components: {len(components)}")
            print(f"  Vulnerabilities: {len(vulns)}")

            if vulns:
                print(f"\n  Sample Vulnerabilities (first 3):")
                for vuln in vulns[:3]:
                    print(f"    - {vuln.get('id', 'N/A')}")

            return True
        else:
            print(f"\n✗ Failed!")
            print(f"Response: {response.text}")
            return False

    except requests.exceptions.ConnectionError:
        print("\n✗ Connection Error - Is the server running?")
        print("  Start with: python3 secure_server.py")
        return False
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    test_export_endpoint()
