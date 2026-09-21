#!/usr/bin/env python3
"""
Export SBOM from Helm in CDX format for a given product version.
"""

import sys
import os
import time
import datetime
import uuid

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'medcrypt-helm-api-sdk/protobuf'))

import requests
from ssl_helper import get_ca_bundle

# Get SSL verification setting
SSL_VERIFY = get_ca_bundle()
from v1.external import heim_organization_pb2 as heim_organization
from v1.external import heim_organization_product_pb2 as heim_org_prod
from v1.external import heim_report_pb2 as heim_report
from config import HELM_API_URL, HELM_WORKSPACE_NAME, HELM_PRODUCT_NAME


def load_api_keys():
    """Load Helm API credentials from environment."""
    return os.environ.get('HELM_CLIENT_ID'), os.environ.get('HELM_CLIENT_SECRET')


def uuid_bytes_to_string(uuid_bytes):
    """Convert UUID bytes to string."""
    return uuid.UUID(int=int.from_bytes(uuid_bytes, 'little'))


def get_organization(client_id, client_secret):
    """Get the default organization."""
    url = f"{HELM_API_URL}/listorganizations"
    headers = {
        'Content-Type': 'application/x-protobuf',
        'client_id': client_id,
        'client_secret': client_secret,
        'env': 'coffee'
    }

    response = requests.post(url, headers=headers, timeout=30, verify=SSL_VERIFY)
    if response.status_code == 200:
        msg = heim_organization.ListOrganizations.FromString(response.content)
        if len(msg.response.orgInfo) > 0:
            return msg.response.orgInfo[0].org, headers
    return None, None


def get_workspace(client_id, client_secret, headers, workspace_name):
    """Get workspace by name."""
    url = f"{HELM_API_URL}/listworkspacesforuser"
    payload = heim_organization.ListWorkspacesForUser()

    response = requests.post(url, data=payload.SerializeToString(), headers=headers, timeout=30, verify=SSL_VERIFY)
    if response.status_code == 200:
        msg = heim_organization.ListWorkspacesForUser.FromString(response.content)
        for ws_info in msg.response.workspace_info:
            if ws_info.workspace.name == workspace_name:
                return ws_info.workspace
    return None


def get_product(headers, org_id, workspace_id, product_name):
    """Get product by name."""
    url = f"{HELM_API_URL}/listorganizationproducts"
    payload = heim_org_prod.ListOrganizationProducts()
    # Handle both UUID object and raw bytes
    if hasattr(org_id, 'uuid'):
        payload.request.organization_id.uuid = org_id.uuid
    else:
        payload.request.organization_id.uuid = org_id

    if workspace_id:
        if hasattr(workspace_id, 'uuid'):
            payload.request.workspace_id.uuid = workspace_id.uuid
        else:
            payload.request.workspace_id.uuid = workspace_id

    response = requests.post(url, data=payload.SerializeToString(), headers=headers, timeout=30, verify=SSL_VERIFY)
    if response.status_code == 200:
        msg = heim_org_prod.ListOrganizationProducts.FromString(response.content)
        for prod in msg.response.organization_product:
            if prod.name == product_name:
                return prod
    return None


def get_product_version(headers, product_id, version_name):
    """Get product version by name."""
    url = f"{HELM_API_URL}/listorganizationproductversions"
    payload = heim_org_prod.ListOrganizationProductVersions()
    # Handle both UUID object and raw bytes
    if hasattr(product_id, 'uuid'):
        payload.request.organization_product_id.uuid = product_id.uuid
    else:
        payload.request.organization_product_id.uuid = product_id

    response = requests.post(url, data=payload.SerializeToString(), headers=headers, timeout=30, verify=SSL_VERIFY)
    if response.status_code == 200:
        msg = heim_org_prod.ListOrganizationProductVersions.FromString(response.content)
        for pv in msg.response.organization_product_version:
            if pv.raw_version_string == version_name:
                return pv
    return None


def request_cdx_export(headers, product_version_id):
    """Request CDX VEX report generation."""
    url = f"{HELM_API_URL}/requestreport"
    payload = heim_report.RequestReport()
    # Handle both UUID object and raw bytes
    if hasattr(product_version_id, 'uuid'):
        payload.request.report_request_data_cyclone_dx_vex.organization_product_version_id.uuid = product_version_id.uuid
    else:
        payload.request.report_request_data_cyclone_dx_vex.organization_product_version_id.uuid = product_version_id

    response = requests.post(url, data=payload.SerializeToString(), headers=headers, timeout=30, verify=SSL_VERIFY)
    if response.status_code == 200:
        msg = heim_report.RequestReport.FromString(response.content)
        report_request_id = msg.response.report_request_id.uuid
        print(f"✓ Report request created: {uuid_bytes_to_string(report_request_id)}")
        return report_request_id
    else:
        print(f"✗ Failed to request report: HTTP {response.status_code}")
        return None


def wait_for_report(headers, report_request_id_uuid, timeout=60):
    """Wait for report to be ready."""
    url = f"{HELM_API_URL}/getreportrequeststate"
    payload = heim_report.GetReportRequestState()
    payload.request.report_request_id.uuid = report_request_id_uuid

    start = datetime.datetime.now()
    end = start + datetime.timedelta(seconds=timeout)

    states = {1: "Pending", 2: "In Progress", 3: "Error", 4: "Completed"}

    while datetime.datetime.now() < end:
        response = requests.post(url, data=payload.SerializeToString(), headers=headers, timeout=30, verify=SSL_VERIFY)
        if response.status_code == 200:
            msg = heim_report.GetReportRequestState.FromString(response.content)
            state = msg.response.report_request_state
            state_name = states.get(state, "Unknown")

            if state == 4:  # Completed
                print(f"✓ Report ready")
                return True
            elif state == 3:  # Error
                print(f"✗ Report generation failed")
                return False
            else:
                print(f"  Waiting... State: {state_name}")
                time.sleep(2)
        else:
            print(f"✗ Error checking state: HTTP {response.status_code}")
            return False

    print(f"✗ Timeout after {timeout} seconds")
    return False


def download_report(headers, report_request_id_uuid, output_path):
    """Download the generated report."""
    url = f"{HELM_API_URL}/getreportfile"
    payload = heim_report.GetReportFile()
    payload.request.report_request_id.uuid = report_request_id_uuid

    response = requests.post(url, data=payload.SerializeToString(), headers=headers, timeout=60, verify=SSL_VERIFY)
    if response.status_code == 200:
        with open(output_path, 'wb') as f:
            f.write(response.content)
        print(f"✓ Downloaded to: {output_path}")
        return True
    else:
        print(f"✗ Failed to download: HTTP {response.status_code}")
        return False


def export_sbom(product_name, version_name, workspace_name=None, output_path=None):
    """
    Export SBOM in CDX format for a product version.

    Args:
        product_name: Name of the product
        version_name: Version string
        workspace_name: Optional workspace name (uses config default if None)
        output_path: Optional output file path (auto-generated if None)

    Returns:
        Path to downloaded file or None on failure
    """
    print("=" * 70)
    print(f"Exporting SBOM: {product_name} v{version_name}")
    print("=" * 70)

    # Load credentials
    client_id, client_secret = load_api_keys()
    if not client_id or not client_secret:
        print("✗ Failed to load API credentials")
        return None

    # Use config defaults if not specified
    if workspace_name is None:
        workspace_name = HELM_WORKSPACE_NAME

    if output_path is None:
        output_path = f"sbom_{product_name.replace(' ', '_')}_v{version_name}.json"

    print(f"\n1. Getting organization...")
    org, headers = get_organization(client_id, client_secret)
    if not org:
        print("✗ Failed to get organization")
        return None
    print(f"✓ Organization: {org.name}")

    print(f"\n2. Getting workspace: {workspace_name}")
    workspace = get_workspace(client_id, client_secret, headers, workspace_name)
    if not workspace:
        print(f"✗ Workspace '{workspace_name}' not found")
        return None
    print(f"✓ Workspace found")

    print(f"\n3. Getting product: {product_name}")
    product = get_product(headers, org.id, workspace.id, product_name)
    if not product:
        print(f"✗ Product '{product_name}' not found")
        return None
    print(f"✓ Product found")

    print(f"\n4. Getting version: {version_name}")
    product_version = get_product_version(headers, product.id, version_name)
    if not product_version:
        print(f"✗ Version '{version_name}' not found")
        return None
    print(f"✓ Version found")

    print(f"\n5. Requesting CDX export...")
    report_request_id = request_cdx_export(headers, product_version.id)
    if not report_request_id:
        return None

    print(f"\n6. Waiting for report generation...")
    if not wait_for_report(headers, report_request_id):
        return None

    print(f"\n7. Downloading report...")
    if download_report(headers, report_request_id, output_path):
        print(f"\n{'=' * 70}")
        print(f"✓ Success! SBOM exported to: {output_path}")
        print(f"{'=' * 70}")
        return output_path

    return None


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='Export SBOM from Helm in CDX format')
    parser.add_argument('--product', required=True, help='Product name')
    parser.add_argument('--version', required=True, help='Version name')
    parser.add_argument('--workspace', help='Workspace name (uses config default if not specified)')
    parser.add_argument('--output', help='Output file path (auto-generated if not specified)')

    args = parser.parse_args()

    result = export_sbom(args.product, args.version, args.workspace, args.output)
    return 0 if result else 1


if __name__ == '__main__':
    sys.exit(main())
