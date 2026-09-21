#!/usr/bin/env python3
"""
Upload SBOM to Helm using device group ID or product version UUID.
"""

import sys
import os
import uuid as uuid_lib

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'medcrypt-helm-api-sdk/protobuf'))

import requests
from ssl_helper import get_ca_bundle

# Get SSL verification setting
SSL_VERIFY = get_ca_bundle()
from v1.external import heim_organization_pb2 as heim_organization
from v1.external import heim_organization_product_pb2 as heim_org_prod
from v1.external import heim_sbom_pb2 as heim_sbom
from config import HELM_API_URL, HELM_WORKSPACE_NAME


def load_api_keys():
    """Load Helm API credentials from environment."""
    return os.environ.get('HELM_CLIENT_ID'), os.environ.get('HELM_CLIENT_SECRET')


def uuid_bytes_to_string(uuid_bytes):
    """Convert UUID bytes to string."""
    return uuid_lib.UUID(int=int.from_bytes(uuid_bytes, 'little'))


def find_product_version_by_device_group_id(device_group_id, workspace_name=None):
    """
    Find product and version where version string = device_group_id.

    Args:
        device_group_id: Device group ID (used as version string)
        workspace_name: Optional workspace name

    Returns:
        Dict with product_name, version, product_uuid, product_version_uuid, and id (bytes)
        or None if not found or not unique
    """
    client_id, client_secret = load_api_keys()
    if not client_id or not client_secret:
        return None

    if workspace_name is None:
        workspace_name = HELM_WORKSPACE_NAME

    auth_headers = {
        'Content-Type': 'application/x-protobuf',
        'client_id': client_id,
        'client_secret': client_secret,
        'env': 'coffee'
    }

    try:
        # Get organization
        url = f"{HELM_API_URL}/listorganizations"
        response = requests.post(url, headers=auth_headers, timeout=30, verify=SSL_VERIFY)
        if response.status_code != 200:
            return None

        msg = heim_organization.ListOrganizations.FromString(response.content)
        if len(msg.response.orgInfo) == 0:
            return None

        org = msg.response.orgInfo[0].org

        # Get workspace if specified
        workspace_uuid = None
        if workspace_name:
            url = f"{HELM_API_URL}/listworkspacesforuser"
            payload = heim_organization.ListWorkspacesForUser()
            response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, timeout=30, verify=SSL_VERIFY)

            if response.status_code == 200:
                msg = heim_organization.ListWorkspacesForUser.FromString(response.content)
                workspaces = [x for x in msg.response.workspace_info if x.workspace.name == workspace_name]
                if len(workspaces) > 0:
                    workspace_uuid = workspaces[0].workspace.id.uuid

        # List all products in workspace/org
        url = f"{HELM_API_URL}/listorganizationproducts"
        payload = heim_org_prod.ListOrganizationProducts()
        payload.request.organization_id.uuid = org.id.uuid
        if workspace_uuid:
            payload.request.workspace_id.uuid = workspace_uuid

        response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, timeout=30, verify=SSL_VERIFY)
        if response.status_code != 200:
            return None

        msg = heim_org_prod.ListOrganizationProducts.FromString(response.content)

        # Search each product's versions for matching device_group_id
        matches = []
        for product in msg.response.organization_product:
            # List versions for this product
            url = f"{HELM_API_URL}/listorganizationproductversions"
            payload = heim_org_prod.ListOrganizationProductVersions()
            payload.request.organization_product_id.uuid = product.id.uuid

            response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, timeout=30, verify=SSL_VERIFY)
            if response.status_code == 200:
                vers_msg = heim_org_prod.ListOrganizationProductVersions.FromString(response.content)

                # Check if any version matches device_group_id
                for pv in vers_msg.response.organization_product_version:
                    if pv.raw_version_string == device_group_id:
                        matches.append({
                            'product_name': product.name,
                            'version': pv.raw_version_string,
                            'product_uuid': str(uuid_bytes_to_string(product.id.uuid)),
                            'product_version_uuid': str(uuid_bytes_to_string(pv.id.uuid)),
                            'id': pv.id.uuid  # Raw bytes for API calls
                        })

        # Return None if not unique (0 or multiple matches)
        if len(matches) != 1:
            return None

        return matches[0]

    except Exception as e:
        print(f"Error: {e}")
        return None


def find_product_version_by_uuid(product_version_uuid, workspace_name=None):
    """
    Find product and version by product version UUID.

    Args:
        product_version_uuid: Product version UUID string
        workspace_name: Optional workspace name

    Returns:
        Dict with product_name, version, product_uuid, product_version_uuid, and id (bytes)
        or None if not found
    """
    client_id, client_secret = load_api_keys()
    if not client_id or not client_secret:
        return None

    if workspace_name is None:
        workspace_name = HELM_WORKSPACE_NAME

    auth_headers = {
        'Content-Type': 'application/x-protobuf',
        'client_id': client_id,
        'client_secret': client_secret,
        'env': 'coffee'
    }

    try:
        # Parse UUID
        try:
            target_uuid = uuid_lib.UUID(product_version_uuid)
        except:
            return None

        # Get organization
        url = f"{HELM_API_URL}/listorganizations"
        response = requests.post(url, headers=auth_headers, timeout=30, verify=SSL_VERIFY)
        if response.status_code != 200:
            return None

        msg = heim_organization.ListOrganizations.FromString(response.content)
        if len(msg.response.orgInfo) == 0:
            return None

        org = msg.response.orgInfo[0].org

        # Get workspace if specified
        workspace_uuid = None
        if workspace_name:
            url = f"{HELM_API_URL}/listworkspacesforuser"
            payload = heim_organization.ListWorkspacesForUser()
            response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, timeout=30, verify=SSL_VERIFY)

            if response.status_code == 200:
                msg = heim_organization.ListWorkspacesForUser.FromString(response.content)
                workspaces = [x for x in msg.response.workspace_info if x.workspace.name == workspace_name]
                if len(workspaces) > 0:
                    workspace_uuid = workspaces[0].workspace.id.uuid

        # List all products
        url = f"{HELM_API_URL}/listorganizationproducts"
        payload = heim_org_prod.ListOrganizationProducts()
        payload.request.organization_id.uuid = org.id.uuid
        if workspace_uuid:
            payload.request.workspace_id.uuid = workspace_uuid

        response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, timeout=30, verify=SSL_VERIFY)
        if response.status_code != 200:
            return None

        msg = heim_org_prod.ListOrganizationProducts.FromString(response.content)

        # Search each product's versions for matching UUID
        for product in msg.response.organization_product:
            url = f"{HELM_API_URL}/listorganizationproductversions"
            payload = heim_org_prod.ListOrganizationProductVersions()
            payload.request.organization_product_id.uuid = product.id.uuid

            response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, timeout=30, verify=SSL_VERIFY)
            if response.status_code == 200:
                vers_msg = heim_org_prod.ListOrganizationProductVersions.FromString(response.content)

                for pv in vers_msg.response.organization_product_version:
                    if uuid_bytes_to_string(pv.id.uuid) == target_uuid:
                        return {
                            'product_name': product.name,
                            'version': pv.raw_version_string,
                            'product_uuid': str(uuid_bytes_to_string(product.id.uuid)),
                            'product_version_uuid': str(uuid_bytes_to_string(pv.id.uuid)),
                            'id': pv.id.uuid  # Raw bytes for API calls
                        }

        return None

    except Exception as e:
        print(f"Error: {e}")
        return None


def upload_sbom(sbom_content, device_group_id=None, product_version_uuid=None,
                workspace_name=None, filename='sbom.json', file_type='CDX'):
    """
    Upload SBOM using device group ID or product version UUID.

    Args:
        sbom_content: SBOM file content as bytes
        device_group_id: Device group ID (version string)
        product_version_uuid: Product version UUID
        workspace_name: Optional workspace name
        filename: SBOM filename
        file_type: SBOM type (CDX or SPDX)

    Returns:
        Dict with status and upload info
    """
    if not device_group_id and not product_version_uuid:
        return {
            'success': False,
            'error': 'Either device_group_id or product_version_uuid required'
        }

    # Find product/version info
    info = None

    if product_version_uuid:
        # Prefer UUID if provided
        info = find_product_version_by_uuid(product_version_uuid, workspace_name)
        if not info:
            return {
                'success': False,
                'error': 'Product version not found'
            }
    elif device_group_id:
        # Use device group ID
        info = find_product_version_by_device_group_id(device_group_id, workspace_name)
        if not info:
            return {
                'success': False,
                'error': 'Device group not found or not unique'
            }

    # Now upload the SBOM
    try:
        client_id, client_secret = load_api_keys()
        if not client_id or not client_secret:
            return {
                'success': False,
                'error': 'Helm API credentials not found'
            }

        auth_headers = {
            'Content-Type': 'application/x-protobuf',
            'client_id': client_id,
            'client_secret': client_secret,
            'env': 'coffee'
        }

        url = f"{HELM_API_URL}/submitsbom"
        payload = heim_sbom.SubmitSbom()
        payload.request.organization_product_version_id.uuid = info['id']
        payload.request.file_type = 1 if file_type == 'SPDX' else 0  # 0=CDX, 1=SPDX
        payload.request.file_name = filename
        payload.request.file_contents = sbom_content

        response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, timeout=60, verify=SSL_VERIFY)

        if response.status_code != 200:
            return {
                'success': False,
                'error': f'Failed to upload SBOM: HTTP {response.status_code}'
            }

        return {
            'success': True,
            'message': f"SBOM uploaded to {info['product_name']} v{info['version']}",
            'product_name': info['product_name'],
            'version': info['version'],
            'product_uuid': info['product_uuid'],
            'product_version_uuid': info['product_version_uuid'],
            'filename': filename,
            'size': len(sbom_content)
        }

    except Exception as e:
        return {
            'success': False,
            'error': f'Failed to upload SBOM: {str(e)}'
        }


def main():
    """Main CLI interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Upload SBOM to Helm',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Upload by device group ID
  %(prog)s --device-group-id cxxxxxxxxxxxxxxxxxxxxxxxx --sbom-file test_sbom.json

  # Upload by product version UUID
  %(prog)s --product-version-uuid 00000000-0000-0000-0000-000000000000 --sbom-file test_sbom.json

  # Specify workspace
  %(prog)s --device-group-id cxxxxxxxxxxxxxxxxxxxxxxxx --sbom-file test_sbom.json --workspace "My Workspace"
"""
    )

    parser.add_argument('--device-group-id',
                       help='Device group ID (version string)')
    parser.add_argument('--product-version-uuid',
                       help='Product version UUID')
    parser.add_argument('--workspace',
                       help='Workspace name (uses config default if not specified)')
    parser.add_argument('--sbom-file', required=True,
                       help='SBOM file to upload')
    parser.add_argument('--file-type', choices=['CDX', 'SPDX'], default='CDX',
                       help='SBOM file type (default: CDX)')

    args = parser.parse_args()

    if not args.device_group_id and not args.product_version_uuid:
        print("Error: Must provide --device-group-id or --product-version-uuid")
        return 1

    if not os.path.exists(args.sbom_file):
        print(f"Error: SBOM file not found: {args.sbom_file}")
        return 1

    # Load SBOM
    with open(args.sbom_file, 'rb') as f:
        sbom_content = f.read()

    print("=" * 70)
    print("Uploading SBOM to Helm")
    print("=" * 70)
    if args.device_group_id:
        print(f"\nDevice Group ID: {args.device_group_id}")
    if args.product_version_uuid:
        print(f"Product Version UUID: {args.product_version_uuid}")
    print(f"SBOM File: {args.sbom_file} ({len(sbom_content)} bytes)")
    print(f"File Type: {args.file_type}")
    print()

    result = upload_sbom(
        sbom_content,
        args.device_group_id,
        args.product_version_uuid,
        args.workspace,
        os.path.basename(args.sbom_file),
        args.file_type
    )

    if result.get('success'):
        print("=" * 70)
        print("✓ Success!")
        print("=" * 70)
        print(f"\nProduct: {result['product_name']}")
        print(f"Version: {result['version']}")
        print(f"Product UUID: {result['product_uuid']}")
        print(f"Version UUID: {result['product_version_uuid']}")
        print(f"File: {result['filename']} ({result['size']} bytes)")
        return 0
    else:
        print("=" * 70)
        print("✗ Failed")
        print("=" * 70)
        print(f"\nError: {result.get('error')}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
