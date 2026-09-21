# Command to retrieve a list of vulnerabilities for a single version of a product.
# make sure you have the python libraries installed on your machine mentioned in the requirements.txt
# Change --client_id and --client_secret to your account username and password. Make sure you escape the special characters if any exists in the client_secret.
      ##Example: "test$how" should be passed in as "test\$how"
# Change the --workspace_name to the workspace name that the product assigned to. This is optional. If not provided, default workspace will be used.
# Change the --product_name to the name of the product that you want to create a version under it.
# Change the --version to the name of the product version that you want to pull the vulnerabilities.
# Change the --api-url to the url of the appropriate environment API gateway base URL.
# Change the --start_date from which the vuln list has to be filtered.
# Change the --end_date to which the vuln list has to be filtered.
# Change the --exploit_source parameter to any supported member of the enumeration. Default is UNDEFINED and this parameter can be omitted.

python3 ../python/vuln_list.py --client_id "xxxxx" --client_secret "xxxxx" --workspace_name "xxxxx" --product_name "xxxxx" --version "xxxxx"  --start_date 'xxxxx' --end_date 'xxxxx' --api_url "xxxxx" --exploit_source=UNDEFINED
