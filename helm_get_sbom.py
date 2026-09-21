#!/usr/bin/env python3
"""
Get SBOM from Helm using device group ID or product version UUID.
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
        Dict with product_name, version, product_uuid, product_version_uuid
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
                            'product_version_uuid': str(uuid_bytes_to_string(pv.id.uuid))
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
        Dict with product_name, version, product_uuid, product_version_uuid
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
                            'product_version_uuid': str(uuid_bytes_to_string(pv.id.uuid))
                        }

        return None

    except Exception as e:
        print(f"Error: {e}")
        return None


def get_sbom(device_group_id=None, product_version_uuid=None, workspace_name=None):
    """
    Get SBOM using device group ID or product version UUID.

    Args:
        device_group_id: Device group ID (version string)
        product_version_uuid: Product version UUID
        workspace_name: Optional workspace name

    Returns:
        Dict with SBOM content or None if not found/not unique
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
            # Return nothing (as requested)
            return None
    elif device_group_id:
        # Use device group ID
        info = find_product_version_by_device_group_id(device_group_id, workspace_name)
        if not info:
            # Return nothing (not found or not unique)
            return None

    # Now export the SBOM
    try:
        from helm_export_sbom import export_sbom
        import tempfile
        import json
        import os

        # Export to temp file
        temp_path = os.path.join(tempfile.gettempdir(), f"sbom_{info['product_version_uuid']}.json")
        result_path = export_sbom(
            info['product_name'],
            info['version'],
            workspace_name,
            temp_path
        )

        if result_path and os.path.exists(result_path):
            with open(result_path, 'r') as f:
                sbom_content = json.load(f)

            # Clean up
            try:
                os.unlink(result_path)
            except:
                pass

            return {
                'success': True,
                'sbom': sbom_content,
                'product_name': info['product_name'],
                'version': info['version'],
                'product_uuid': info['product_uuid'],
                'product_version_uuid': info['product_version_uuid']
            }

        return None

    except Exception as e:
        print(f"Error exporting SBOM: {e}")
        return None


def main():
    """Main CLI interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Get SBOM from Helm',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Get by device group ID
  %(prog)s --device-group-id cxxxxxxxxxxxxxxxxxxxxxxxx

  # Get by product version UUID
  %(prog)s --product-version-uuid 00000000-0000-0000-0000-000000000000

  # Both (UUID takes precedence)
  %(prog)s --device-group-id cxxxxxxxxxxxxxxxxxxxxxxxx --product-version-uuid 00000000-0000-0000-0000-000000000000
"""
    )

    parser.add_argument('--device-group-id',
                       help='Device group ID (version string)')
    parser.add_argument('--product-version-uuid',
                       help='Product version UUID')
    parser.add_argument('--workspace',
                       help='Workspace name (uses config default if not specified)')
    parser.add_argument('--output', '-o',
                       help='Output file path (prints to stdout if not specified)')

    args = parser.parse_args()

    if not args.device_group_id and not args.product_version_uuid:
        print("Error: Must provide --device-group-id or --product-version-uuid")
        return 1

    result = get_sbom(args.device_group_id, args.product_version_uuid, args.workspace)

    if not result:
        print("No SBOM found (not found or not unique)")
        return 1

    if not result.get('success'):
        print(f"Error: {result.get('error')}")
        return 1

    # Output SBOM
    import json
    sbom_json = json.dumps(result['sbom'], indent=2)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(sbom_json)
        print(f"SBOM written to {args.output}")
    else:
        print(sbom_json)

    return 0


def get_vulnerabilities_for_product_version(product_version_uuid, client_id, client_secret):
    """
    Get vulnerabilities for a product version from Helm.

    Args:
        product_version_uuid: Product version UUID
        client_id: Helm API client ID
        client_secret: Helm API client secret

    Returns:
        Dict with success, vulnerabilities list, and error
    """
    try:
        # Import protobuf for vulnerabilities
        from v1.external import heim_vuln_pb2 as heim_vuln
        from google.protobuf.json_format import MessageToDict

        # Convert UUID string to bytes
        if isinstance(product_version_uuid, str):
            product_version_uuid_obj = uuid_lib.UUID(product_version_uuid)
            uuid_bytes = product_version_uuid_obj.int.to_bytes(16, 'little')
        else:
            uuid_bytes = product_version_uuid

        # Setup auth headers
        auth_headers = {
            'Content-Type': 'application/x-protobuf',
            'client_id': client_id,
            'client_secret': client_secret
        }

        # Create request
        url = f"{HELM_API_URL}/listvulnerabilities"
        payload = heim_vuln.ListVulnerabilities()
        payload.request.page.page = 0
        payload.request.page.items = 10000  # Max items
        payload.request.filter.organization_product_version_id.uuid = uuid_bytes

        # Make request
        response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, verify=SSL_VERIFY)

        if response.status_code == 200:
            msg = heim_vuln.ListVulnerabilities.FromString(response.content)

            # Convert to dict
            vulnerabilities = []
            for vuln in msg.response.vulnerability:
                vuln_dict = MessageToDict(vuln, preserving_proto_field_name=True)
                vulnerabilities.append(vuln_dict)

            return {
                'success': True,
                'vulnerabilities': vulnerabilities,
                'total_count': msg.response.total_count
            }
        else:
            return {
                'success': False,
                'error': f'HTTP {response.status_code}: {response.text}',
                'vulnerabilities': []
            }

    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'vulnerabilities': []
        }


if __name__ == '__main__':
    sys.exit(main())
