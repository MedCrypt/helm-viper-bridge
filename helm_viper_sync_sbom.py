#!/usr/bin/env python3
"""
Helm <-> Viper SBOM Sync Script

Upload SBOM to Helm and sync with Viper device group.
Uses the existing Helm SDK for protobuf communication.
"""

import argparse
import json
import os
import sys
import subprocess
import requests

def load_api_keys():
    """Load API keys from environment."""
    return os.environ.get('HELM_CLIENT_ID'), os.environ.get('HELM_CLIENT_SECRET'), os.environ.get('VIPER_API_KEY')


def upload_sbom_to_helm(sbom_file, product_name, version, client_id, client_secret, workspace_name=None):
    """
    Upload SBOM using the Helm SDK upload script.

    Returns:
        product_version_uuid if successful, None otherwise
    """
    sdk_path = "medcrypt-helm-api-sdk/api/python/upload_sbom.py"

    if not os.path.exists(sdk_path):
        print(f"Error: Helm SDK not found at {sdk_path}")
        return None

    # Build command
    cmd = [
        'python3',
        sdk_path,
        '--client_id', client_id,
        '--client_secret', client_secret,
        '--product_name', product_name,
        '--version', version,
        '--sbom_files', sbom_file,
        '--createProd',
        '--createProdVers'
    ]

    if workspace_name:
        cmd.extend(['--workspace_name', workspace_name])

    print(f"Uploading SBOM to Helm...")
    print(f"  Product: {product_name}")
    print(f"  Version: {version}")
    print(f"  File: {sbom_file}")

    try:
        # Run the upload script
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode == 0:
            print("✓ SBOM uploaded successfully to Helm")
            print(result.stdout)

            # Parse output to extract product version UUID
            # The SDK should print the UUID in the output
            # Look for UUID pattern in output
            import re
            uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
            matches = re.findall(uuid_pattern, result.stdout, re.IGNORECASE)

            if matches:
                product_version_uuid = matches[-1]  # Last UUID is usually the product version
                print(f"✓ Product Version UUID: {product_version_uuid}")
                return product_version_uuid
            else:
                print("⚠ Could not extract product version UUID from output")
                print("Please check Helm dashboard for the product version UUID")
                return None
        else:
            print(f"✗ Error uploading SBOM: {result.stderr}")
            return None

    except subprocess.TimeoutExpired:
        print("✗ Upload timed out after 60 seconds")
        return None
    except Exception as e:
        print(f"✗ Error: {e}")
        return None


def update_viper_device_group(device_group_id, helm_sbom_id, viper_api_key):
    """
    Update Viper device group with Helm SBOM ID.
    """
    url = f"https://viper-xi.vercel.app/api/devicegroups/{device_group_id}/updatehelmid"

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {viper_api_key}'
    }

    payload = {
        'helmSbomId': helm_sbom_id
    }

    print(f"\nUpdating Viper device group...")
    print(f"  Device Group ID: {device_group_id}")
    print(f"  Helm SBOM ID: {helm_sbom_id}")

    try:
        response = requests.put(url, json=payload, headers=headers, timeout=30)

        if response.status_code == 200:
            print("✓ Viper device group updated successfully")
            try:
                data = response.json()
                print(f"  Response: {json.dumps(data, indent=2)}")
                return True
            except:
                print(f"  Response: {response.text}")
                return True
        else:
            print(f"✗ Error updating Viper: HTTP {response.status_code}")
            print(f"  Response: {response.text}")
            return False

    except requests.Timeout:
        print("✗ Request timed out")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Upload SBOM to Helm and sync with Viper device group'
    )

    parser.add_argument('--sbom-file', required=True,
                       help='Path to SBOM file (JSON or XML)')
    parser.add_argument('--product', required=True,
                       help='Helm product name')
    parser.add_argument('--version', required=True,
                       help='Product version')
    parser.add_argument('--device-group-id', required=True,
                       help='Viper device group ID')
    parser.add_argument('--workspace',
                       help='Helm workspace name (optional)')
    parser.add_argument('--helm-sbom-id',
                       help='Use existing Helm product version UUID (skip upload)')

    args = parser.parse_args()

    print("=" * 70)
    print("Helm <-> Viper SBOM Sync")
    print("=" * 70)

    # Load API keys
    helm_id, helm_secret, viper_key = load_api_keys()

    if not viper_key:
        print("✗ Error: Viper API key not found")
        print("  Create viper_api_key.txt with your Viper API key")
        return 1

    helm_sbom_id = args.helm_sbom_id

    # Step 1: Upload to Helm (if not provided)
    if not helm_sbom_id:
        if not helm_id or not helm_secret:
            print("✗ Error: Helm API credentials not found")
            print("  Create mc_api_key.txt with:")
            print("    Line 1: client_id")
            print("    Line 2: client_secret")
            return 1

        if not os.path.exists(args.sbom_file):
            print(f"✗ Error: SBOM file not found: {args.sbom_file}")
            return 1

        helm_sbom_id = upload_sbom_to_helm(
            args.sbom_file,
            args.product,
            args.version,
            helm_id,
            helm_secret,
            args.workspace
        )

        if not helm_sbom_id:
            print("\n✗ Failed to upload SBOM to Helm")
            print("  You can retry with --helm-sbom-id <uuid> to skip upload")
            return 1
    else:
        print(f"Using provided Helm SBOM ID: {helm_sbom_id}")

    # Step 2: Update Viper
    success = update_viper_device_group(
        args.device_group_id,
        helm_sbom_id,
        viper_key
    )

    print("\n" + "=" * 70)
    if success:
        print("✓ Sync completed successfully!")
        print(f"  Helm Product Version UUID: {helm_sbom_id}")
        print(f"  Viper Device Group ID: {args.device_group_id}")
    else:
        print("✗ Sync failed")
        print(f"  Helm SBOM ID: {helm_sbom_id}")
        print("  Use this ID to retry: --helm-sbom-id " + helm_sbom_id)
    print("=" * 70)

    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
