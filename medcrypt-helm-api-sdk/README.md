## SDK prerequisites
    - Install python3
    - pip3 install -r requirements.txt (this installs the required python modules)

## Steps to execute APIs
    - Make sure the prerequisite steps are successful.
    - Download the medcrypt-helm-api-sdk zip
    - Validate the file downloaded via the hash provided on the website

## Executing scripts against Helm API
    - CD into the directory api/run
    - There are four scripts: run_upload_sbom.sh, run_unmatched_sbom_entries.sh, run_vuln_list.sh, and run_product_version_report.sh
    - Please make sure to follow best practices for managing the secrets.
    - Each script parameters need to be updated as stated below,

## Execute run_upload_sbom.sh script
    - Users can upload single or multiple sboms using this script.
    - Descriptions on each command line parameter used in this script,
         --client_id and --client_secret - your api account username and password.
         --workspace_name - name of the workspace that the product assigned to. This is optional. If not provided, default workspace will be used.
         --sbom_files - path of the sbom file located on your system. To upload multiple sboms files, all the file paths need to be space separated. 
         --product_name - name of the product that you want to create a version under.
         --createProd - pass this parameter if the product doesn't exist already and you want to create a new product.
         --version - name of the product version that you want to create and upload an sbom.
         --createProdVers - pass this parameter if the version doesn't exist already and you want to create a new product version.
         --api_url - https://helm.medcrypt.co/api-gw/v1
         --file_type - This needs to be set to SPDX only if you want to upload an SPDX sbom. 
           If this parameter is either skipped or set to any text other than SPDX, the uploaded file will be treated as CDX file type.  
    - Set the parameters as needed and run ./run_upload_sbom.sh

## Execute run_unmatched_sbom_entries.sh script
    - This script lists all the unmatched sbom entries for a given product and product version.
    - Descriptions on each command line parameter used in this script,
         --client_id and --client_secret - your api account username and password.
         --workspace_name - name of the workspace that the product assigned to. This is optional. If not provided, default workspace will be used.
         --product_name - name of the product that you want to pull the unmatched sbom entries for.
         --version - name of the product version that you want to pull the unmatched sbom entries for.
         --api_url - https://helm.medcrypt.co/api-gw/v1
    - Set the parameters as needed and run ./run_unmatched_sbom_entries.sh

## Execute run_vuln_list.sh script
    - This script lists all the vulnerabilities for a given product and product version. 
    - Descriptions on each command line parameter used in this script,
        --client_id and --client_secret - your api account username and password.
        --workspace_name - name of the workspace that the product assigned to. This is optional. If not provided, default workspace will be used.
        --product_name - name of the product that you want to pull the vulnerabilities for.
        --version - name of the product version that you want to pull the vulnerabilities for.
        --api_url - https://helm.medcrypt.co/api-gw/v1
    - date parameters if you want to pull vulnerabilities for a given time frame,
        --start_date from which the vuln list should be filtered.
        --end_date to which the vuln list should be filtered.
    - if you wish to filter the list of vulnerabilities to only those that have known exploits, you can specify the source of the exploit information.
        --exploit_source - default is UNDEFINED. We currently support CISA_KEV.
    - Set the parameters as needed and run ./run_vuln_list.sh

## Execute run_product_version_report.sh script
    - This script creates and downloads a report that is specific to a product and a product version. 
    - Descriptions on each command line parameter used in this script,
        --client_id and --client_secret - your api account username and password.
        --workspace_name - name of the workspace that the product assigned to. This is optional. If not provided, default workspace will be used.
        --product_name - name of the product that you want to pull the vulnerabilities for.
        --version - name of the product version that you want to pull the vulnerabilities for.
        --api_url - https://helm.medcrypt.co/api-gw/v1
        --file_path - Where to save the generated report.
        --report_type - which report to generate. Currently supported values are FDA_EXCEL and CDX_VEX. 
        --report_id, - a unique identifier for the generated VEX report. If not provided, default will be used.
    - Set the parameters as needed and run ./run_product_version_report.sh

# API involved and their definitions

## listorganizations
    - This lists the organizations that the user has access to.
## listworkspacesforuser
    - This lists the workspaces that the user has access to in the organization.
## listorganizationproducts
    - This lists the organization products for a given organization
## listorganizationproductversions
    - This lists the organization product versions for a given organization product
## createorganizationproduct
    - This creates the organization product with the name provided under the organization that the user has access to.
## createorganizationproductversions
    - This creates the organization product version with the version name provided under a selected product.
## submitsbom
    - This uploads an sbom provided in the --sbom_files parameter.
    - Users can upload an sbom under an existing product and product version.
    - Users can create a new product, product version and upload an sbom under the newly created product version.
    - Users can upload multiple sboms in a single request by passing them space separated.
## listunmatchedsbomentries
    - This lists all the unmatched sbom entries for a given product and product version.
## listvulnerabilities
    - This lists all the vulnerabilities for a given product and product version and also for a given time frame.
## requestreport
    - Issues a request to generate a product version report. The report generation process is asynchronous.
## getreportrequeststate
    - Checks on the status of a requested report.
## getreportfile
    - Once a report request is in a completed state (report_request_state = 4), the file will be available for download.