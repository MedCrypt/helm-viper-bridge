# Command to run the sbom upload.
# make sure you have the python libraries installed on your machine mentioned in the requirements.txt
# Change --client_id and --client_secret to your account username and password. Make sure you escape the special characters if any exists in the client_secret.
      ##Example: "test$how" should be passed in as "test\$how"
# Change the --workspace_name to the workspace name that the product assigned to. This is optional. If not provided, default workspace will be used.
# Change the --sbom_files to your sbom file path located on your system.
# Change the --product_name to the name of the product that you want to create a version under it.
# Change the --version to the name of the product version that you want to create and upload sbom.
# Change the --api-url to the url of the appropriate environment API gateway base URL.
# --file_type set this to SPDX if the file type is SPDX. By default api supports CDX types.
python3 ../python/upload_sbom.py --client_id "xxxxx" --client_secret "xxxxx" --workspace_name "xxxxx" --sbom_files "xxxxx" --createProd --product_name "xxxxx" --createProdVers  --version "xxxxx"  --api_url "xxxxx"