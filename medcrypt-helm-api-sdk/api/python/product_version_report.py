
import argparse
import datetime
import os
import requests
import sys
import time
import uuid

# import generated files
generated_src_dir = "../../protobuf"
# manually add protobuf path to system paths for inline import statements
sys.path.insert(0, generated_src_dir)
from v1.external import heim_organization_pb2 as heim_organization
from v1.external import heim_organization_product_pb2 as heim_org_prod
from v1.external import heim_report_pb2 as heim_report

parser = argparse.ArgumentParser(
    prog='Helm - Generate Product Version Report',
    description='Requests that a specific type of product version report be generated and downloaded',
    epilog='')

parser.add_argument('-id', '--client_id', help="The client's id used to authenticate", required=True)
parser.add_argument('-secret', '--client_secret', help="The client's secret used to authenticate", required=True)
parser.add_argument('-wn', '--workspace_name', help="The workspace name that the product assigned to")
parser.add_argument('-pn', '--product_name', help="The product name to list the vulnerabilities", required=True)
parser.add_argument('-v', '--version', help="The version to list the vulnerabilities", required=True)
parser.add_argument('-f', '--file_path', help="Where to store the downloaded file", required=True)
parser.add_argument('-type', '--report_type', help="Which type of report to generate (CDX_VEX or FDA_EXCEL)", choices=['CDX_VEX', 'FDA_EXCEL'], default='CDX_VEX')
parser.add_argument('-a', '--api_url', help="The api url. Defaults to https://helm.medcrypt.co/api-gw/v1",
                    default="https://helm.medcrypt.co/api-gw/v1")
parser.add_argument('-ri', '--report_id', help="A unique identifier for the generated report")

# Add ability to skip tls verification for local/dev testing
parser.add_argument('--no_verify', dest='verify', action='store_false',
                    help="Set this flag to disable tls verification. (Don't do this unless you absolutely need to!)")
parser.set_defaults(verify=True)

args = parser.parse_args()

base_url = args.api_url
destination_path = args.file_path
verify = args.verify

CLIENT_ID = args.client_id
CLIENT_SECRET = args.client_secret


if CLIENT_ID is None or CLIENT_SECRET is None:
    #TODO: how accurate is this error message?
    sys.exit("Must set HELM_CLIENT_ID and HELM_CLIENT_SECRET as environment variables")

workspace_name, product_name, version, report_id =  args.workspace_name, args.product_name, args.version, args.report_id

if product_name is None:
    sys.exit("Please specify product name")


#region Helper Functions

def uuid_bytes_to_string(uuid_bytes):
    return uuid.UUID(int=int.from_bytes(uuid_bytes, 'little'))

# The PascalCased is used for API endpoints in local env scripts as local doesn't have API Gateway set up yet.
# So the API calls directly hit our Helm endpoints hence PascalCased.
# TODO: Ideally, we should replicate all the AWS  services involved in this workflow (API gateway, Lambda and Cloud Front)
# in localstack so that endpoints are lowercased everywhere.
# First, invest sometime on researching how much effort is required to implement all needed AWS services in lcoalstack and go from there

def get_default_organization(base_url, headers, verify):
    url = base_url + "/listorganizations"
    response = requests.post(url, headers=headers, verify=verify)
    if response.status_code == 200:
        payload = heim_organization.ListOrganizations.FromString(response.content)
        return [payload.response.orgInfo][0][0].org
    return None

def get_product_by_name(org_uuid, workspace_name, product_name, base_url, headers, verify):
    if workspace_name:
        # get the workspaces for this organization for the user
        url = base_url + "/listworkspacesforuser"
        payload = heim_organization.ListWorkspacesForUser()
        response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, verify=args.verify)

        if response.status_code == 200:
            msg = heim_organization.ListWorkspacesForUser.FromString(response.content)
            if workspace_name is not None:
                print(f"\nLooking up the workspace with name: {workspace_name} ")
                workspaces = [x for x in msg.response.workspace_info if x.workspace.name == workspace_name]
                if len(workspaces) == 0:
                    sys.exit(f"No such workspace with name: {workspace_name}")
                elif len(workspaces) > 0:
                    workspace = workspaces[0]
                    print(f"Workspace {workspace.workspace.name} exists." )
                    is_ws_admin = workspace.is_ws_admin
                    workspace_uuid = workspace.workspace.id.uuid

        else :
            sys.exit("Error listing the workspaces for the user.")

    url = base_url + "/listorganizationproducts"
    payload = heim_org_prod.ListOrganizationProducts()
    payload.request.organization_id.uuid = org_uuid
    if workspace_name:
        payload.request.workspace_id.uuid = workspace_uuid
    response = requests.post(url, data=payload.SerializeToString(), headers=headers, verify=verify)
    if response.status_code == 200:
        msg = heim_org_prod.ListOrganizationProducts.FromString(response.content)
        print(f"\nLooking up the product with name: {product_name} ")
        products = [x for x in msg.response.organization_product if x.name == product_name]
        if len(products) > 0:
            return products[0]
        return None

def get_product_version_by_name(org_prod_uuid, version_name, base_url, headers, verify):
    url = base_url + "/listorganizationproductversions"
    payload = heim_org_prod.ListOrganizationProductVersions()
    payload.request.organization_product_id.uuid = org_prod_uuid
    response = requests.post(url, data=payload.SerializeToString(), headers=headers, verify=verify)
    if response.status_code == 200:
        msg = heim_org_prod.ListOrganizationProductVersions.FromString(response.content)
        print(f"Looking up product version with name: {version_name}")
        product_versions = [x for x in msg.response.organization_product_version if x.raw_version_string == version_name]
        if len(product_versions) > 0:
            return product_versions[0]
        return None

def request_report_creation(org_prod_vers_uuid, report_type, base_url, headers, verify, report_id):
    url = base_url + "/requestreport"
    payload = heim_report.RequestReport()
    if report_type == 'CDX_VEX':
        payload.request.report_request_data_cyclone_dx_vex.organization_product_version_id.uuid = org_prod_vers_uuid
        if report_id:
            payload.request.report_request_data_cyclone_dx_vex.unique_cdx_vex_report_id = report_id

    elif report_type == 'FDA_EXCEL':
        payload.request.report_request_data_fda.organization_product_version_id.uuid = org_prod_vers_uuid
    else:
        print(f"Unsupported report type {report_type}")
        return None
    response = requests.post(url, data=payload.SerializeToString(), headers=headers, verify = verify)
    if response.status_code == 200:
        msg = heim_report.RequestReport.FromString(response.content)
        encoded_uuid = msg.response.report_request_id.uuid
        print(f"Report Request {uuid_bytes_to_string(encoded_uuid)} created")
        return encoded_uuid
    else:
        print(f"Status code of {response.status_code} received")
        return None

def wait_for_report_ready(report_request_uuid, base_url, headers, verify, timeout_seconds=30):
    '''
    Waits for the report to be in a ready state, as indicated by the report_request_state.
    1 = Pending
    2 = In Progress
    3 = Error
    4 = Completed
    '''
    start_datetime = datetime.datetime.now()
    end_datetime = start_datetime + datetime.timedelta(seconds=timeout_seconds)
    url = base_url + "/getreportrequeststate"
    payload = heim_report.GetReportRequestState()
    payload.request.report_request_id.uuid = report_request_uuid
    while True:
        if datetime.datetime.now() > end_datetime:
            print(f"{timeout_seconds} seconds timeout elapsed, exiting")
            return f"Report was not ready within timeout of {timeout_seconds} seconds"
        print("Waiting for report ready...")
        response = requests.post(url, data=payload.SerializeToString(), headers=headers, verify=verify)
        if response.status_code == 200:
            msg = heim_report.GetReportRequestState.FromString(response.content)
            request_report_state = msg.response.report_request_state
            if request_report_state == 4:
                return None
            print(f"Request Report State {request_report_state}, sleeping and trying again...")
            time.sleep(2)
        else:
            return f"Status code {response.status_code} received"

def download_report(report_request_uuid, base_url, headers, destination_path, verify):
    url = base_url + "/getreportfile"
    payload = heim_report.GetReportFile()
    payload.request.report_request_id.uuid = report_request_uuid
    response = requests.post(url, data=payload.SerializeToString(), headers=headers, verify=verify)
    if response.status_code == 200:
        # save file
        full_path = os.path.expanduser(destination_path)
        with open(full_path, "wb") as binary_file:
            binary_file.write(response.content)
            return full_path
    else:
        print(f"Status code {response.status_code} received")
        return None
#endregion


auth_headers =  {
        'Content-Type': 'application/x-protobuf',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }

org = get_default_organization(base_url=base_url, headers=auth_headers, verify=verify)
org
if org is None:
    sys.exit(f"Client ID {CLIENT_ID} is not associated with an organization")

product = get_product_by_name(org_uuid=org.id.uuid, workspace_name=workspace_name, product_name=product_name, base_url=base_url, headers=auth_headers, verify=verify)
if product is None:
    sys.exit(f"No such product with name: {product_name}")

product_uuid = uuid_bytes_to_string(product.id.uuid)

product_version = get_product_version_by_name(org_prod_uuid=product.id.uuid, version_name=version, base_url=base_url, headers=auth_headers, verify=verify)
if product_version is None:
    sys.exit(f"No such product version with name:  {version}" )

report_request_id = request_report_creation(org_prod_vers_uuid=product_version.id.uuid, report_type=args.report_type, base_url=base_url, headers=auth_headers, verify=verify, report_id=report_id)
if report_request_id is None:
    sys.exit("Failed to generate a report request")

ready_response = wait_for_report_ready(report_request_uuid=report_request_id, base_url=base_url, headers=auth_headers, verify=verify)
if ready_response is not None:
    sys.exit(f"Error waiting for report to be ready: {ready_response}")

full_path = download_report(report_request_uuid=report_request_id, base_url=base_url, headers=auth_headers, destination_path=destination_path, verify=verify)
if full_path is None:
    sys.exit("Unable to download file")

print(f"Report generated and saved at {full_path}")




