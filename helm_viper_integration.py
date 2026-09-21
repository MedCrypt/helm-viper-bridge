#!/usr/bin/env python3
"""
Helm <-> Viper Integration Module

Handles uploading SBOMs to Helm and syncing with Viper device groups.
"""

import json
import os
import requests
from typing import Dict, Optional, Tuple
from ssl_helper import get_ca_bundle

# API Configuration
HELM_API_URL = "https://helm.medcrypt.co/api-gw/v1"
VIPER_API_URL = "https://viper-xi.vercel.app/api"

# Get SSL verification setting
SSL_VERIFY = get_ca_bundle()

def load_api_keys() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Load API keys from environment."""
    return os.environ.get('HELM_CLIENT_ID'), os.environ.get('HELM_CLIENT_SECRET'), os.environ.get('VIPER_API_KEY')


def upload_sbom_to_helm(
    sbom_content: bytes,
    product_name: str,
    version: str,
    client_id: str,
    client_secret: str,
    workspace_name: Optional[str] = None,
    file_type: str = "CDX"
) -> Dict:
    """
    Upload SBOM to Helm API and return product version UUID.

    Args:
        sbom_content: SBOM file content as bytes
        product_name: Name of the product
        version: Version string
        client_id: Helm API client ID
        client_secret: Helm API client secret
        workspace_name: Optional workspace name
        file_type: SBOM type (CDX or SPDX)

    Returns:
        Dict with status and product_version_uuid
    """
    try:
        # Note: This is a simplified version. The actual Helm API uses protobuf.
        # For full implementation, you'd need to use the SDK in medcrypt-helm-api-sdk/

        auth_headers = {
            'Content-Type': 'application/json',
            'client_id': client_id,
            'client_secret': client_secret
        }

        # Simplified approach - in reality, you'd use the upload_sbom.py script
        # or integrate the protobuf SDK directly

        return {
            'success': False,
            'error': 'Direct Helm API integration requires protobuf SDK. Use helm_viper_sync_sbom.py instead.',
            'note': 'Run: python3 helm_viper_sync_sbom.py --sbom-file path/to/sbom.json --product MyProduct --version 1.0.0'
        }

    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }


def list_viper_device_groups(viper_api_key: str) -> Dict:
    """
    List all Viper device groups.

    Args:
        viper_api_key: Viper API key

    Returns:
        Dict with device groups list
    """
    try:
        url = f"{VIPER_API_URL}/v1/devicegroups"

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {viper_api_key}'
        }

        response = requests.get(url, headers=headers, verify=SSL_VERIFY)

        if response.status_code == 200:
            data = response.json()
            # Viper API returns {items: [...]}
            items = data.get('items', []) if isinstance(data, dict) else data
            return {
                'success': True,
                'device_groups': items,
                'count': len(items)
            }
        else:
            return {
                'success': False,
                'error': f'HTTP {response.status_code}: {response.text}'
            }

    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }


def update_viper_device_group(
    device_group_id: str,
    helm_sbom_id: str,
    viper_api_key: str
) -> Dict:
    """
    Update Viper device group with Helm SBOM ID.

    Args:
        device_group_id: Viper device group ID
        helm_sbom_id: Helm product version UUID
        viper_api_key: Viper API key

    Returns:
        Dict with status
    """
    try:
        url = f"{VIPER_API_URL}/v1/devicegroups/{device_group_id}/updatehelmid"

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {viper_api_key}'
        }

        payload = {
            'helmSbomId': helm_sbom_id
        }

        response = requests.put(url, json=payload, headers=headers, verify=SSL_VERIFY)

        if response.status_code == 200:
            return {
                'success': True,
                'device_group_id': device_group_id,
                'helm_sbom_id': helm_sbom_id,
                'response': response.json() if response.text else {}
            }
        else:
            return {
                'success': False,
                'error': f'HTTP {response.status_code}: {response.text}',
                'device_group_id': device_group_id
            }

    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }


def get_sbom_from_helm(
    product_version_uuid: str,
    client_id: str,
    client_secret: str
) -> Dict:
    """
    Retrieve SBOM from Helm API given product version UUID.

    Args:
        product_version_uuid: Helm product version UUID
        client_id: Helm API client ID
        client_secret: Helm API client secret

    Returns:
        Dict with SBOM data
    """
    try:
        # Note: Actual implementation would use Helm API endpoints
        # This requires the protobuf SDK

        return {
            'success': False,
            'error': 'SBOM retrieval requires Helm SDK integration',
            'note': 'Use the medcrypt-helm-api-sdk scripts directly'
        }

    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }


def sync_helm_to_viper(
    sbom_file_path: str,
    product_name: str,
    version: str,
    device_group_id: str
) -> Dict:
    """
    Full workflow: Upload SBOM to Helm, then sync to Viper.

    Args:
        sbom_file_path: Path to SBOM file
        product_name: Helm product name
        version: Product version
        device_group_id: Viper device group ID

    Returns:
        Dict with complete workflow results
    """
    result = {
        'helm_upload': None,
        'viper_update': None,
        'success': False
    }

    # Load API keys
    helm_id, helm_secret, viper_key = load_api_keys()

    if not helm_id or not helm_secret:
        result['error'] = 'Helm API credentials not configured (HELM_CLIENT_ID / HELM_CLIENT_SECRET)'
        return result

    if not viper_key:
        result['error'] = 'Viper API key not configured (VIPER_API_KEY)'
        return result

    if not os.path.exists(sbom_file_path):
        result['error'] = f'SBOM file not found: {sbom_file_path}'
        return result

    # Read SBOM file
    with open(sbom_file_path, 'rb') as f:
        sbom_content = f.read()

    # Step 1: Upload to Helm
    print(f"Uploading SBOM to Helm for {product_name} v{version}...")
    helm_result = upload_sbom_to_helm(
        sbom_content,
        product_name,
        version,
        helm_id,
        helm_secret
    )
    result['helm_upload'] = helm_result

    if not helm_result.get('success'):
        return result

    helm_sbom_id = helm_result.get('product_version_uuid')
    if not helm_sbom_id:
        result['error'] = 'No product version UUID returned from Helm'
        return result

    # Step 2: Update Viper
    print(f"Updating Viper device group {device_group_id} with Helm SBOM ID {helm_sbom_id}...")
    viper_result = update_viper_device_group(
        device_group_id,
        helm_sbom_id,
        viper_key
    )
    result['viper_update'] = viper_result

    result['success'] = viper_result.get('success', False)

    return result


if __name__ == '__main__':
    # Test API key loading
    helm_id, helm_secret, viper_key = load_api_keys()

    print("API Key Status:")
    print(f"  Helm Client ID: {'✓ Loaded' if helm_id else '✗ Missing'}")
    print(f"  Helm Client Secret: {'✓ Loaded' if helm_secret else '✗ Missing'}")
    print(f"  Viper API Key: {'✓ Loaded' if viper_key else '✗ Missing'}")
