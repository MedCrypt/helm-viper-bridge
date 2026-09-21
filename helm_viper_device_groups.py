#!/usr/bin/env python3
"""
Get device groups that have product versions in Helm.
Matches device groups from Viper with product versions in Helm workspace.
"""

import sys
import os
import uuid as uuid_lib

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'medcrypt-helm-api-sdk/protobuf'))

import requests
from ssl_helper import get_ca_bundle
from v1.external import heim_organization_pb2 as heim_organization
from v1.external import heim_organization_product_pb2 as heim_org_prod
from config import HELM_API_URL, HELM_WORKSPACE_NAME

# Get SSL verification setting
SSL_VERIFY = get_ca_bundle()


def load_api_keys():
    """Load Helm API credentials from environment."""
    return os.environ.get('HELM_CLIENT_ID'), os.environ.get('HELM_CLIENT_SECRET')


def load_viper_api_key():
    """Load Viper API key from environment."""
    return os.environ.get('VIPER_API_KEY')


def uuid_bytes_to_string(uuid_bytes):
    """Convert UUID bytes to string."""
    return str(uuid_lib.UUID(int=int.from_bytes(uuid_bytes, 'little')))


def get_viper_device_groups(viper_api_key):
    """
    Get all device groups from Viper.

    Returns:
        List of device groups with id, name, cpe, sbomHelmId
    """
    try:
        url = "https://viper-xi.vercel.app/api/v1/devicegroups"
        headers = {
            'Authorization': f'Bearer {viper_api_key}',
            'Content-Type': 'application/json'
        }

        # Viper paginates device groups; follow pages until hasNextPage is False
        all_items = []
        page = 1
        while True:
            response = requests.get(
                url, headers=headers,
                params={'page': page, 'pageSize': 100},
                timeout=30, verify=SSL_VERIFY
            )

            if response.status_code != 200:
                break

            data = response.json()
            all_items.extend(data.get('items', []))

            if not data.get('hasNextPage'):
                break
            page += 1

        return all_items

    except Exception as e:
        print(f"Error getting Viper device groups: {e}")
        return []


def get_helm_product_versions(workspace_name=None):
    """
    Get all product versions from Helm workspace.

    Returns:
        Dict mapping version_string -> {product_name, version_string, product_version_uuid}
    """
    client_id, client_secret = load_api_keys()
    if not client_id or not client_secret:
        return {}

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
            return {}

        msg = heim_organization.ListOrganizations.FromString(response.content)
        if len(msg.response.orgInfo) == 0:
            return {}

        org = msg.response.orgInfo[0].org

        # Get workspace
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

        # List all products in workspace
        url = f"{HELM_API_URL}/listorganizationproducts"
        payload = heim_org_prod.ListOrganizationProducts()
        payload.request.organization_id.uuid = org.id.uuid
        if workspace_uuid:
            payload.request.workspace_id.uuid = workspace_uuid

        response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, timeout=30, verify=SSL_VERIFY)
        if response.status_code != 200:
            return {}

        msg = heim_org_prod.ListOrganizationProducts.FromString(response.content)

        # Build map of version_string -> product info
        version_map = {}
        for product in msg.response.organization_product:
            # List versions for this product
            url = f"{HELM_API_URL}/listorganizationproductversions"
            payload = heim_org_prod.ListOrganizationProductVersions()
            payload.request.organization_product_id.uuid = product.id.uuid

            response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, timeout=30, verify=SSL_VERIFY)
            if response.status_code == 200:
                vers_msg = heim_org_prod.ListOrganizationProductVersions.FromString(response.content)

                for pv in vers_msg.response.organization_product_version:
                    version_string = pv.raw_version_string
                    version_map[version_string] = {
                        'product_name': product.name,
                        'version_string': version_string,
                        'product_version_uuid': uuid_bytes_to_string(pv.id.uuid)
                    }

        return version_map

    except Exception as e:
        print(f"Error getting Helm product versions: {e}")
        return {}


def get_matched_device_groups(viper_api_key):
    """
    Get device groups that have matching product versions in Helm.

    Returns:
        List of matched records with device group info + Helm info
    """
    # Get device groups from Viper
    device_groups = get_viper_device_groups(viper_api_key)

    # Get product versions from Helm
    helm_versions = get_helm_product_versions()

    # Match device groups with Helm versions
    matched = []
    for dg in device_groups:
        device_group_id = dg.get('id')

        # Check if this device group ID matches a Helm version string
        if device_group_id in helm_versions:
            helm_info = helm_versions[device_group_id]

            matched.append({
                'id': device_group_id,
                'cpe': dg.get('cpe'),
                'helmProductName': helm_info['product_name'],
                'helmProductVersionName': helm_info['version_string'],
                'helmSbomId': helm_info['product_version_uuid']
            })

    return matched


if __name__ == '__main__':
    # Test the function
    viper_key = load_viper_api_key()
    if viper_key:
        matched = get_matched_device_groups(viper_key)
        print(f"Found {len(matched)} matched device groups:")
        for m in matched:
            print(f"  - {m['name']}: {m['helmProductName']} v{m['helmProductVersionName']}")
    else:
        print("Error: Viper API key not found")
