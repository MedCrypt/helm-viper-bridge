import argparse
import datetime
import requests
import sys
import uuid

from util.flags_enum_parser_action import FlagsEnumParseAction
from vulns.exploit_sources import ExploitSource

# import generated files
generated_src_dir = "../../protobuf"
sys.path.insert(0, generated_src_dir)
from v1.external import heim_organization_pb2 as heim_organization
from v1.external import heim_organization_product_pb2 as heim_org_prod
from v1.external import heim_vuln_pb2 as heim_vuln
from google.protobuf.json_format import MessageToJson

parser = argparse.ArgumentParser(
    prog='Helm - List vulnerabilities for a product version',
    description='This script lists the unmatched SBOM entries.',
    epilog='')

parser.add_argument('-id', '--client_id', help="The client's id used to authenticate", required=True)
parser.add_argument('-secret', '--client_secret', help="The client's secret used to authenticate", required=True)
parser.add_argument('-wn', '--workspace_name', help="The workspace name that the product assigned to")
parser.add_argument('-pn', '--product_name', help="The product name to list the vulnerabilities", required=True)
parser.add_argument('-v', '--version', help="The version to list the vulnerabilities", required=True)
parser.add_argument('-sd','--start_date',type=lambda s: datetime.datetime.strptime(s, '%m-%d-%Y'))
parser.add_argument('-ed','--end_date',type=lambda s: datetime.datetime.strptime(s, '%m-%d-%Y'))
parser.add_argument('-a', '--api_url', help="The api url. Defaults to https://helm.medcrypt.co/api-gw/v1",
                    default="https://helm.medcrypt.co/api-gw/v1")
# Add ability to skip tls verification for local/dev testing
parser.add_argument('--no_verify', dest='verify', action='store_false',
                    help="Set this flag to disable tls verification. (Don't do this unless you absolutely need to!)")
parser.add_argument('-xs','--exploit_source', type=ExploitSource, action=FlagsEnumParseAction, default=ExploitSource.UNDEFINED,
                    help="The exploit source to restrict the vulnerability list. Optional.")

parser.set_defaults(verify=True)

args = parser.parse_args()

base_url = args.api_url

CLIENT_ID = args.client_id
CLIENT_SECRET = args.client_secret



if CLIENT_ID is None or CLIENT_SECRET is None:
    sys.exit("Must set HELM_CLIENT_ID and HELM_CLIENT_SECRET as environment variables")

# helper for turning binary UUIDs to strings for human consumption
def uuid_bytes_to_string(uuid_bytes):
    return uuid.UUID(int=int.from_bytes(uuid_bytes, 'little'))

# Grab a token
headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}


workspace_name, product_name,  version =  args.workspace_name, args.product_name, args.version

# sanity check product lookup info
if product_name is None:
    sys.exit("Please specify product name")




# Get the valid organizations
url = base_url + "/listorganizations"
auth_headers = {
    'Content-Type': 'application/x-protobuf',
    'client_id': CLIENT_ID,
    'client_secret': CLIENT_SECRET
}
response = requests.post(url, headers=auth_headers, verify=args.verify)
if response.status_code  == 200:
    msg = heim_organization.ListOrganizations.FromString(response.content)
    # get the org
    org = [msg.response.orgInfo][0][0].org
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

    # get the orgProducts
    url = base_url + "/listorganizationproducts"
    payload = heim_org_prod.ListOrganizationProducts()
    payload.request.organization_id.uuid = org.id.uuid
    if workspace_name:
        payload.request.workspace_id.uuid = workspace_uuid
    response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, verify=args.verify)

    if response.status_code == 200:
        msg = heim_org_prod.ListOrganizationProducts.FromString(response.content)
        if product_name is not None:
            print(f"\nLooking up the product with name: {product_name} ")
            products = [x for x in msg.response.organization_product if x.name == product_name]
            if len(products) == 0:
                sys.exit(f"No such product with name: {product_name}")
            elif len(products) > 0:
                product = products[0]
                print("Found!")


        product_uuid = uuid_bytes_to_string(product.id.uuid)

        # get the orgProductVersions and ensure it exists
        url = base_url + "/listorganizationproductversions"
        payload = heim_org_prod.ListOrganizationProductVersions()
        payload.request.organization_product_id.uuid = product.id.uuid

        response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, verify=args.verify)
        if response.status_code == 200:
            msg = heim_org_prod.ListOrganizationProductVersions.FromString(response.content)

            print(f"Looking up product version with name: {version} ")

            product_versions = [x for x in msg.response.organization_product_version if x.raw_version_string == version]
            if len(product_versions) > 0:
                product_version = product_versions[0]
                print("Found!")

            # can't proceed if product version does not exist
            if len(product_versions) == 0:
                sys.exit(f"No such product version with name:  {version}" )

            url = base_url + "/listvulnerabilities"
            payload = heim_vuln.ListVulnerabilities()
            #TODO: Ideally we don't need pagination for an API user. So for now just setting it 10k items which is the configured max limit
            payload.request.page.page = 0
            payload.request.page.items = 10000
            payload.request.filter.organization_product_version_id.uuid = product_version.id.uuid
            #For start and end date filters, proto datatype is long.
            #In python, time is in seconds but Java expects it to be in milliseconds hence multiply with 1000
            if args.start_date is not None:
                payload.request.filter.start_date = int(round(args.start_date.timestamp()*1000))
            if args.end_date is not None:
                payload.request.filter.end_date = int(round(args.end_date.timestamp()*1000))
            if args.exploit_source & ExploitSource.CISA_KEV == ExploitSource.CISA_KEV:
                payload.request.filter.cisa_kev_only = True

            response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, verify=args.verify)
            msg = heim_vuln.ListVulnerabilities.FromString(response.content)

            print("\nresponse_content: " + str(MessageToJson(msg))+"\n")

    else :
         print("listorganizationproducts Response: " + str(response.status_code) )

else :
    print("listorganizations Response: " + str(response.status_code) )



