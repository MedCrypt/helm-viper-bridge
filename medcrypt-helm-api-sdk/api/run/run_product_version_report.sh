# Command to request and download a report for a specific product version.
# make sure you have the python libraries installed on your machine mentioned in the requirements.txt
# Change --client_id and --client_secret to your account username and password. Make sure you escape the special characters if any exists in the client_secret.
      ##Example: "test$how" should be passed in as "test\$how"
# Change the --workspace_name to the workspace name that the product assigned to. This is optional. If not provided, default workspace will be used.
# Change the --product_name to the name of the product for the report
# Change the --version to the name of the product VERSION for the report.
# Change the --api_url to the url of the appropriate environment API gateway base URL.
# Change the --report_type, if needed
# Change the --file_path to the destination where you would like the file stored.
# Change the --report_id, a unique identifier for the generated VEX report. If not provided, default will be used.
python3 ../python/product_version_report.py --client_id "xxxxx" --client_secret "xxxxx" --workspace_name "xxxxx" --product_name "xxxxx" --version "xxxxx" --api_url "xxxxx" --file_path "xxxxx" --report_type "xxxxx" --report_id "xxxxx"