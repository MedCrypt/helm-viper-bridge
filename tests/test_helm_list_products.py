#!/usr/bin/env python3
"""
Test script to list products from Helm API.
"""

import sys
import os
import uuid

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'medcrypt-helm-api-sdk/protobuf'))

import requests
from v1.external import heim_organization_pb2 as heim_organization
from v1.external import heim_organization_product_pb2 as heim_org_prod
from config import HELM_API_URL, HELM_WORKSPACE_NAME

# Load API credentials
def load_api_keys():
    """Load Helm API credentials."""
    if not os.path.exists('mc_api_key.txt'):
        print("Error: mc_api_key.txt not found")
        print("Create it with:")
        print("  Line 1: client_id")
        print("  Line 2: client_secret")
        return None, None

    with open('mc_api_key.txt', 'r') as f:
        lines = f.read().strip().split('\n')
        if len(lines) >= 2:
            return lines[0].strip(), lines[1].strip()
        elif ':' in lines[0]:
            parts = lines[0].split(':')
            return parts[0].strip(), parts[1].strip() if len(parts) > 1 else None

    return None, None

def test_list_organizations(client_id, client_secret):
    """Test listing organizations."""
    print("\n" + "=" * 70)
    print("Testing: List Organizations")
    print("=" * 70)

    url = f"{HELM_API_URL}/listorganizations"

    auth_headers = {
        'Content-Type': 'application/x-protobuf',
        'client_id': client_id,
        'client_secret': client_secret,
        'env': 'coffee'
    }

    try:
        response = requests.post(url, headers=auth_headers, timeout=30)

        if response.status_code == 200:
            msg = heim_organization.ListOrganizations.FromString(response.content)
            print(f"✓ Status: {response.status_code}")
            print(f"\nOrganizations found: {len(msg.response.orgInfo)}")

            for idx, org_info in enumerate(msg.response.orgInfo):
                print(f"\n  Organization {idx + 1}:")
                print(f"    Name: {org_info.org.name}")
                try:
                    # Try converting bytes to UUID
                    if isinstance(org_info.org.id, bytes):
                        org_uuid = uuid.UUID(int=int.from_bytes(org_info.org.id, 'little'))
                    else:
                        org_uuid = org_info.org.id
                    print(f"    ID: {org_uuid}")
                except Exception as e:
                    print(f"    ID: (could not convert: {e})")

            return msg.response.orgInfo[0].org if len(msg.response.orgInfo) > 0 else None
        else:
            print(f"✗ Error: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            print(f"Response Headers:")
            for header, value in response.headers.items():
                print(f"  {header}: {value}")
            return None

    except Exception as e:
        print(f"✗ Error: {e}")
        return None

def test_list_workspaces(client_id, client_secret, workspace_name=None):
    """Test listing workspaces."""
    print("\n" + "=" * 70)
    print("Testing: List Workspaces")
    print("=" * 70)

    # Use workspace from config if not provided
    if workspace_name is None:
        workspace_name = HELM_WORKSPACE_NAME

    url = f"{HELM_API_URL}/listworkspacesforuser"

    auth_headers = {
        'Content-Type': 'application/x-protobuf',
        'client_id': client_id,
        'client_secret': client_secret,
        'env': 'coffee'
    }

    payload = heim_organization.ListWorkspacesForUser()

    try:
        response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, timeout=30)

        if response.status_code == 200:
            msg = heim_organization.ListWorkspacesForUser.FromString(response.content)
            print(f"✓ Status: {response.status_code}")
            print(f"\nWorkspaces found: {len(msg.response.workspace_info)}")

            target_workspace = None
            for idx, ws_info in enumerate(msg.response.workspace_info):
                is_target = ws_info.workspace.name == workspace_name
                marker = " ← TARGET" if is_target else ""
                print(f"\n  Workspace {idx + 1}:{marker}")
                print(f"    Name: {ws_info.workspace.name}")
                try:
                    if isinstance(ws_info.workspace.id, bytes):
                        ws_uuid = uuid.UUID(int=int.from_bytes(ws_info.workspace.id, 'little'))
                    else:
                        ws_uuid = ws_info.workspace.id
                    print(f"    ID: {ws_uuid}")
                except Exception as e:
                    print(f"    ID: (could not convert: {e})")

                if is_target:
                    target_workspace = ws_info.workspace

            if target_workspace:
                print(f"\n✓ Found target workspace: {workspace_name}")
            else:
                print(f"\n⚠ Target workspace '{workspace_name}' not found")

            return target_workspace
        else:
            print(f"✗ Error: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            return None

    except Exception as e:
        print(f"✗ Error: {e}")
        return None

def test_list_products(client_id, client_secret, workspace=None):
    """Test listing products."""
    print("\n" + "=" * 70)
    print("Testing: List Organization Products")
    print("=" * 70)

    url = f"{HELM_API_URL}/listorganizationproducts"

    auth_headers = {
        'Content-Type': 'application/x-protobuf',
        'client_id': client_id,
        'client_secret': client_secret,
        'env': 'coffee'
    }

    payload = heim_org_prod.ListOrganizationProducts()

    if workspace:
        payload.request.workspace_id.CopyFrom(workspace.id)
        print(f"Filtering by workspace: {workspace.name}")

    try:
        response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, timeout=30)

        if response.status_code == 200:
            msg = heim_org_prod.ListOrganizationProducts.FromString(response.content)
            print(f"✓ Status: {response.status_code}")
            print(f"\nProducts found: {len(msg.response.organization_product)}")

            if len(msg.response.organization_product) == 0:
                print("\n⚠ No products found in this workspace")
                print("  You may need to create a product first")
            else:
                for idx, prod in enumerate(msg.response.organization_product):
                    print(f"\n  Product {idx + 1}:")
                    print(f"    Name: {prod.name}")
                    try:
                        if isinstance(prod.id, bytes):
                            prod_uuid = uuid.UUID(int=int.from_bytes(prod.id, 'little'))
                        else:
                            prod_uuid = prod.id
                        print(f"    ID: {prod_uuid}")
                    except Exception as e:
                        print(f"    ID: (could not convert: {e})")

            return msg.response.organization_product
        else:
            print(f"✗ Error: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            return None

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    print("=" * 70)
    print("Helm API Test - List Products")
    print("=" * 70)

    # Load credentials
    print("\nLoading API credentials...")
    client_id, client_secret = load_api_keys()

    if not client_id or not client_secret:
        print("✗ Failed to load API credentials")
        return 1

    print(f"✓ Client ID: {client_id[:10]}...")
    print(f"✓ Client Secret: {'*' * 10}")

    # Test 1: List organizations
    org = test_list_organizations(client_id, client_secret)
    if not org:
        print("\n✗ Failed to list organizations")
        return 1

    # Test 2: List workspaces
    workspace = test_list_workspaces(client_id, client_secret)
    if not workspace:
        print(f"\n⚠ Could not find workspace '{HELM_WORKSPACE_NAME}', listing all products")

    # Test 3: List products
    products = test_list_products(client_id, client_secret, workspace)

    print("\n" + "=" * 70)
    print("Test Complete!")
    print("=" * 70)

    return 0

if __name__ == '__main__':
    sys.exit(main())
