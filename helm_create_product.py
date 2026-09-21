#!/usr/bin/env python3
"""
Create Helm product and version, optionally upload SBOM.

For Viper integration: product_name = device group name, version = device group ID.
"""

import sys
import os
import uuid
import base64

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
    return uuid.UUID(int=int.from_bytes(uuid_bytes, 'little'))


def create_helm_product_and_version(
    product_name,
    version,
    workspace_name=None,
    sbom_content=None,
    sbom_filename=None,
    file_type='CDX'
):
    """
    Create Helm product and version, optionally upload SBOM.

    Args:
        product_name: Name of product to create
        version: Version string (e.g., device group ID)
        workspace_name: Optional workspace name (uses config default if None)
        sbom_content: Optional SBOM file content as bytes
        sbom_filename: Optional filename for SBOM
        file_type: SBOM type (CDX or SPDX)

    Returns:
        Dict with status and product/version UUIDs
    """
    result = {
        'success': False,
        'product_name': product_name,
        'version': version,
        'steps': []
    }

    # Load credentials
    client_id, client_secret = load_api_keys()
    if not client_id or not client_secret:
        result['error'] = 'Helm API credentials not found'
        return result

    # Use config default if workspace not specified
    if workspace_name is None:
        workspace_name = HELM_WORKSPACE_NAME

    auth_headers = {
        'Content-Type': 'application/x-protobuf',
        'client_id': client_id,
        'client_secret': client_secret,
        'env': 'coffee'
    }

    try:
        # Step 1: Get organization
        result['steps'].append('Getting organization...')
        url = f"{HELM_API_URL}/listorganizations"
        response = requests.post(url, headers=auth_headers, timeout=30, verify=SSL_VERIFY)

        if response.status_code != 200:
            result['error'] = f'Failed to get organization: HTTP {response.status_code}'
            return result

        msg = heim_organization.ListOrganizations.FromString(response.content)
        if len(msg.response.orgInfo) == 0:
            result['error'] = 'No organizations found'
            return result

        org = msg.response.orgInfo[0].org
        result['organization'] = org.name
        result['steps'].append(f'✓ Organization: {org.name}')

        # Step 2: Get workspace
        workspace_uuid = None
        if workspace_name:
            result['steps'].append(f'Getting workspace: {workspace_name}...')
            url = f"{HELM_API_URL}/listworkspacesforuser"
            payload = heim_organization.ListWorkspacesForUser()
            response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, timeout=30, verify=SSL_VERIFY)

            if response.status_code == 200:
                msg = heim_organization.ListWorkspacesForUser.FromString(response.content)
                workspaces = [x for x in msg.response.workspace_info if x.workspace.name == workspace_name]
                if len(workspaces) > 0:
                    workspace_uuid = workspaces[0].workspace.id.uuid
                    result['workspace'] = workspace_name
                    result['steps'].append(f'✓ Workspace found: {workspace_name}')
                else:
                    result['error'] = f'Workspace not found: {workspace_name}'
                    return result

        # Step 3: Check if product exists
        result['steps'].append(f'Checking if product exists: {product_name}...')
        url = f"{HELM_API_URL}/listorganizationproducts"
        payload = heim_org_prod.ListOrganizationProducts()
        payload.request.organization_id.uuid = org.id.uuid
        if workspace_uuid:
            payload.request.workspace_id.uuid = workspace_uuid

        response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, timeout=30, verify=SSL_VERIFY)

        if response.status_code != 200:
            result['error'] = f'Failed to list products: HTTP {response.status_code}'
            return result

        msg = heim_org_prod.ListOrganizationProducts.FromString(response.content)
        products = [x for x in msg.response.organization_product if x.name == product_name]

        # Step 4: Create product if it doesn't exist
        if len(products) == 0:
            result['steps'].append(f'Creating product: {product_name}...')
            url = f"{HELM_API_URL}/createorganizationproduct"
            payload = heim_org_prod.CreateOrganizationProduct()
            payload.request.name = product_name
            if workspace_uuid:
                payload.request.workspace_id.uuid = workspace_uuid

            response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, timeout=30, verify=SSL_VERIFY)

            if response.status_code != 200:
                result['error'] = f'Failed to create product: HTTP {response.status_code}'
                return result

            msg = heim_org_prod.CreateOrganizationProduct.FromString(response.content)

            # Handle archived product
            if msg.response.organization_product.name == "Archived Item Found":
                result['steps'].append('Product was archived, unarchiving...')
                url = f"{HELM_API_URL}/createorunarchiveorganizationproduct"
                payload = heim_org_prod.CreateOrUnarchiveOrganizationProduct()
                payload.request.unarchiveProd = False
                payload.request.organization_id.uuid = org.id.uuid
                payload.request.org_prod_id.uuid = msg.response.organization_product.id.uuid
                if workspace_uuid:
                    payload.request.workspace_id.uuid = workspace_uuid

                response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, timeout=30, verify=SSL_VERIFY)
                msg = heim_org_prod.CreateOrUnarchiveOrganizationProduct.FromString(response.content)

            if msg.response.metadata.status == 2:
                result['error'] = 'Not authorized to create product'
                return result

            product = msg.response.organization_product
            result['steps'].append(f'✓ Product created: {product_name}')
            result['product_created'] = True
        else:
            product = products[0]
            result['steps'].append(f'✓ Product already exists: {product_name}')
            result['product_created'] = False

        product_uuid = uuid_bytes_to_string(product.id.uuid)
        result['product_uuid'] = str(product_uuid)

        # Step 5: Check if version exists
        result['steps'].append(f'Checking if version exists: {version}...')
        url = f"{HELM_API_URL}/listorganizationproductversions"
        payload = heim_org_prod.ListOrganizationProductVersions()
        payload.request.organization_product_id.uuid = product.id.uuid

        response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, timeout=30, verify=SSL_VERIFY)

        if response.status_code != 200:
            result['error'] = f'Failed to list versions: HTTP {response.status_code}'
            return result

        msg = heim_org_prod.ListOrganizationProductVersions.FromString(response.content)
        product_versions = [x for x in msg.response.organization_product_version if x.raw_version_string == version]

        # Step 6: Create version if it doesn't exist
        if len(product_versions) == 0:
            result['steps'].append(f'Creating version: {version}...')
            url = f"{HELM_API_URL}/createorganizationproductversion"
            payload = heim_org_prod.CreateOrganizationProductVersion()
            payload.request.organization_product_id.uuid = product.id.uuid
            payload.request.raw_version_string = version

            response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, timeout=30, verify=SSL_VERIFY)

            if response.status_code != 200:
                result['error'] = f'Failed to create version: HTTP {response.status_code}'
                return result

            msg = heim_org_prod.CreateOrganizationProductVersion.FromString(response.content)

            # Handle archived version
            if msg.response.organization_product_version.raw_version_string == "Archived Item Found":
                result['steps'].append('Version was archived, unarchiving...')
                url = f"{HELM_API_URL}/createorunarchiveorganizationproductversion"
                payload = heim_org_prod.CreateOrUnarchiveOrganizationProductVersion()
                payload.request.unarchiveProdVers = False
                payload.request.organization_product_id.uuid = msg.response.organization_product_version.organization_product_id.uuid
                payload.request.organization_product_vers_id.uuid = msg.response.organization_product_version.id.uuid

                response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, timeout=30, verify=SSL_VERIFY)
                msg = heim_org_prod.CreateOrUnarchiveOrganizationProductVersion.FromString(response.content)

            if msg.response.metadata.status == 2:
                result['error'] = 'Not authorized to create version'
                return result

            product_version = msg.response.organization_product_version
            result['steps'].append(f'✓ Version created: {version}')
            result['version_created'] = True
        else:
            product_version = product_versions[0]
            result['steps'].append(f'✓ Version already exists: {version}')
            result['version_created'] = False

        product_version_uuid = uuid_bytes_to_string(product_version.id.uuid)
        result['product_version_uuid'] = str(product_version_uuid)

        # Step 7: Upload SBOM if provided
        if sbom_content:
            result['steps'].append('Uploading SBOM...')
            url = f"{HELM_API_URL}/submitsbom"
            payload = heim_sbom.SubmitSbom()
            payload.request.organization_product_version_id.uuid = product_version.id.uuid
            payload.request.file_type = 1 if file_type == 'SPDX' else 0  # 0=CDX, 1=SPDX
            payload.request.file_name = sbom_filename or 'sbom.json'
            payload.request.file_contents = sbom_content

            response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, timeout=60, verify=SSL_VERIFY)

            if response.status_code != 200:
                result['error'] = f'Failed to upload SBOM: HTTP {response.status_code}'
                result['sbom_uploaded'] = False
                # Don't fail completely, product/version were created
            else:
                result['steps'].append('✓ SBOM uploaded successfully')
                result['sbom_uploaded'] = True

        result['success'] = True
        return result

    except Exception as e:
        result['error'] = str(e)
        import traceback
        result['traceback'] = traceback.format_exc()
        return result


def main():
    """Main CLI interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Create Helm product and version',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create product/version for Viper device group (no SBOM)
  %(prog)s --product-name "acme:sample-scanner" --version "cxxxxxxxxxxxxxxxxxxxxxxxx"

  # Create with SBOM upload
  %(prog)s --product-name "my-device" --version "1.0" --sbom-file sbom.json

  # Specify workspace
  %(prog)s --product-name "my-device" --version "1.0" --workspace "My Workspace"
"""
    )

    parser.add_argument('--product-name', required=True,
                       help='Product name (e.g., device group name)')
    parser.add_argument('--version', required=True,
                       help='Version string (e.g., device group ID)')
    parser.add_argument('--workspace',
                       help='Workspace name (uses config default if not specified)')
    parser.add_argument('--sbom-file',
                       help='Optional SBOM file to upload')
    parser.add_argument('--file-type', choices=['CDX', 'SPDX'], default='CDX',
                       help='SBOM file type (default: CDX)')

    args = parser.parse_args()

    # Load SBOM if provided
    sbom_content = None
    sbom_filename = None
    if args.sbom_file:
        if not os.path.exists(args.sbom_file):
            print(f"✗ Error: SBOM file not found: {args.sbom_file}")
            return 1

        with open(args.sbom_file, 'rb') as f:
            sbom_content = f.read()
        sbom_filename = os.path.basename(args.sbom_file)

    # Create product and version
    print("=" * 70)
    print(f"Creating Helm Product and Version")
    print("=" * 70)
    print(f"\nProduct: {args.product_name}")
    print(f"Version: {args.version}")
    if args.workspace:
        print(f"Workspace: {args.workspace}")
    if sbom_content:
        print(f"SBOM: {sbom_filename} ({len(sbom_content)} bytes)")
    print()

    result = create_helm_product_and_version(
        args.product_name,
        args.version,
        args.workspace,
        sbom_content,
        sbom_filename,
        args.file_type
    )

    # Print results
    for step in result.get('steps', []):
        print(step)

    print()
    if result.get('success'):
        print("=" * 70)
        print("✓ Success!")
        print("=" * 70)
        print(f"\nProduct UUID: {result.get('product_uuid')}")
        print(f"Version UUID: {result.get('product_version_uuid')}")
        if result.get('product_created'):
            print(f"\nProduct '{args.product_name}' was created")
        if result.get('version_created'):
            print(f"Version '{args.version}' was created")
        if result.get('sbom_uploaded'):
            print("SBOM was uploaded")
        return 0
    else:
        print("=" * 70)
        print("✗ Failed")
        print("=" * 70)
        print(f"\nError: {result.get('error')}")
        if 'traceback' in result:
            print(f"\nTraceback:\n{result['traceback']}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
