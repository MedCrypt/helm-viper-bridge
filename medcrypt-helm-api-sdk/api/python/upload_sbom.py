import argparse
import os
import requests
import sys
import uuid

# import generated files
generated_src_dir = "../../protobuf"
sys.path.insert(0, generated_src_dir)
from v1.external import heim_organization_pb2 as heim_organization
from v1.external import heim_organization_product_pb2 as heim_org_prod
from v1.external import heim_sbom_pb2 as heim_sbom
from google.protobuf.json_format import MessageToJson

parser = argparse.ArgumentParser(
    prog='Helm SBOM Upload',
    description='This tool will create a new version and upload the SBOM to it.',
    epilog='')

parser.add_argument('-id', '--client_id', help="The client's id used to authenticate", required=True)
parser.add_argument('-secret', '--client_secret', help="The client's secret used to authenticate", required=True)
parser.add_argument('-wn', '--workspace_name', help="The workspace name that the product assigned to")
parser.add_argument('-ft', '--file_type', help="SBOM file type")
parser.add_argument("--sbom_files", nargs="+", help="SBOM file to upload")
parser.add_argument('-p', '--product', help="The product ID to upload this SBOM to")
parser.add_argument('-pn', '--product_name', help="The product name to upload this SBOM to", required=True)
parser.add_argument('-v', '--version', help="The version to create and upload this SBOM to", required=True)
parser.add_argument('-cp', '--createProd', help="Boolean flag to let user create the product if it does not exist", action=argparse.BooleanOptionalAction)
parser.add_argument('-cpv', '--createProdVers', help="Boolean flag to let user create the product version if it does not exist", action=argparse.BooleanOptionalAction)
parser.add_argument('-a', '--api_url', help="The api url. Defaults to https://helm.medcrypt.co/api-gw/v1",
                    default="https://helm.medcrypt.co/api-gw/v1")
# Add ability to skip tls verification for local/dev testing
parser.add_argument('--no_verify', dest='verify', action='store_false',
                    help="Set this flag to disable tls verification. (Don't do this unless you absolutely need to!)")
parser.set_defaults(verify=True)

args = parser.parse_args()

base_url = args.api_url

CLIENT_ID = args.client_id
CLIENT_SECRET = args.client_secret

createProd = args.createProd
createProdVers = args.createProdVers

if CLIENT_ID is None or CLIENT_SECRET is None:
    sys.exit("Must set HELM_CLIENT_ID and HELM_CLIENT_SECRET as environment variables")

# helper for turning binary UUIDs to strings for human consumption
def uuid_bytes_to_string(uuid_bytes):
    return uuid.UUID(int=int.from_bytes(uuid_bytes, 'little'))

# Grab a token
headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}


files, workspace_name, product_name, product_id, version = args.sbom_files, args.workspace_name, args.product_name, args.product, args.version
file_type = args.file_type
if file_type == "SPDX" :
    ftVal = 1
else :
    ftVal = 0

# sanity check product lookup info
#if workspace_name is None:
#    sys.exit("Please specify the workspace name that the product is assigned to")
if product_name is not None and product_id is not None:
    sys.exit("Please specify ONLY product id OR product name")
elif product_name is None and product_id is None:
    sys.exit("Please specify a product id or product name")

# check if files exist
for file in files:
    if not os.path.isfile(file):
        sys.exit(f"Could not find file {file} ")


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
                print(f"No such product with name: {product_name}")
            elif len(products) > 0:
                product = products[0]
                print(f"Product already exists:  {product_name}" )

        elif product_id is not None:
            print(f"\nLooking up the product with id: {product_id} ")
            product_id = uuid.UUID(product_id)  # convert to correct type
            products = [x for x in msg.response.organization_product if uuid_bytes_to_string(x.id.uuid) == product_id]
            if len(products) == 0:
                print(f"No such product with id '{product_id}'")
            elif len(products) > 0:
                product = products[0]
                print(f"Product already exists:  {product.name}" )


        #create product if product does not exist and user specify so
        if len(products) == 0 :
             if (createProd) :
                print("Creating the product with name: " + product_name)
                url = base_url + "/createorganizationproduct"
                payload = heim_org_prod.CreateOrganizationProduct()
                payload.request.name = product_name
                if workspace_name:
                    payload.request.workspace_id.uuid = workspace_uuid
                response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, verify=args.verify)

                msg = heim_org_prod.CreateOrganizationProduct.FromString(response.content)
                if msg.response.organization_product.name == "Archived Item Found" :
                    url = base_url + "/createorunarchiveorganizationproduct"
                    payload = heim_org_prod.CreateOrUnarchiveOrganizationProduct()
                    payload.request.unarchiveProd = False
                    payload.request.organization_id.uuid = org.id.uuid
                    payload.request.org_prod_id.uuid = msg.response.organization_product.id.uuid
                    if workspace_name:
                        payload.request.workspace_id.uuid = workspace_uuid
                    response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, verify=args.verify)
                    msg = heim_org_prod.CreateOrUnarchiveOrganizationProduct.FromString(response.content)
                if msg.response.metadata.status == 2:
                    sys.exit("User is not authorized to create the product.\n" )
                else :
                    print("Done creating the product with name: " + product_name)
                product = msg.response.organization_product
             else :
                sys.exit("You have opted to not to create the product if it does not exist. To force create, update --no-createProd to --createProd. ")

        product_uuid = uuid_bytes_to_string(product.id.uuid)

        # get the orgProductVersions and ensure it does not  exist
        url = base_url + "/listorganizationproductversions"
        payload = heim_org_prod.ListOrganizationProductVersions()
        payload.request.organization_product_id.uuid = product.id.uuid

        response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, verify=args.verify)
        if response.status_code == 200:
            msg = heim_org_prod.ListOrganizationProductVersions.FromString(response.content)

            print(f"Looking up product version with name: {version} ")

            product_versions = [x for x in msg.response.organization_product_version if x.raw_version_string == version]
            if len(product_versions) > 0:
                print(f"Version already exists: {version}")
                product_version = product_versions[0]

            # create a new version if version does not exist and user specify so
            if len(product_versions) == 0:
                print(f"No such product version with name:  {version}" )
                if (createProdVers) :
                    print(f"Creating the product version  with name: {version}")
                    url = base_url + "/createorganizationproductversion"
                    payload = heim_org_prod.CreateOrganizationProductVersion()
                    payload.request.organization_product_id.uuid = product.id.uuid
                    payload.request.raw_version_string = version
                    response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, verify=args.verify)
                    msg = heim_org_prod.CreateOrganizationProductVersion.FromString(response.content)
                    if msg.response.organization_product_version.raw_version_string == "Archived Item Found" :
                        url = base_url + "/createorunarchiveorganizationproductversion"
                        payload = heim_org_prod.CreateOrUnarchiveOrganizationProductVersion()
                        payload.request.unarchiveProdVers = False
                        payload.request.organization_product_id.uuid = msg.response.organization_product_version.organization_product_id.uuid
                        payload.request.organization_product_vers_id.uuid = msg.response.organization_product_version.id.uuid
                        response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, verify=args.verify)
                        msg = heim_org_prod.CreateOrUnarchiveOrganizationProductVersion.FromString(response.content)
                    if msg.response.metadata.status == 2:
                        sys.exit("\nUser is not authorized to create the product version.\n" )
                    else :
                        print("Done creating the product version with name: " + version)
                    product_version = msg.response.organization_product_version
                else :
                    sys.exit("You have opted to not to create the product version if it does not exist. To force create, update --no-createProdVers to --createProdVers. ")

            # upload the sboms
            for sbom_file_path in files:
                with open(sbom_file_path, "rb") as file:
                    print("Uploading the SBOM " + sbom_file_path)
                    url = base_url + "/submitsbom"
                    payload = heim_sbom.SubmitSbom()
                    payload.request.organization_product_version_id.uuid = product_version.id.uuid
                    payload.request.file_type = ftVal
                    payload.request.file_name = sbom_file_path
                    payload.request.file_contents = file.read()
                    response = requests.post(url, data=payload.SerializeToString(), headers=auth_headers, verify=args.verify)
                    msg = heim_sbom.SubmitSbom.FromString(response.content)
                    print("\nresponse_content: " + str(MessageToJson(msg)))
            print("Done uploading the SBOM successfully under version name: " + version+".")

    else :
         print("listorganizationproducts Response: " + str(response.status_code) )

else :
    print("listorganizations Response: " + str(response.status_code) )



