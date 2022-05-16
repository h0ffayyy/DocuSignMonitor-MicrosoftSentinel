# DocuSign Monitor Integration for Microsoft Sentinel

Author: Aaron Hoffmann

Note: This is an unofficial solution for DocuSign Monitor. The original author is not affiliated with DocuSign.

DocuSign Monitor is a solution for DocuSign administrators to gain better visibility into their eSign organization and accounts. This Microsoft Sentinel Solution provides the ability to ingest events from the Monitor stream and receive alerts based on DocuSign Monitor-generated alerts.

## Solution resources

The DocuSign Monitor solution consists of the following resources:

* Data connector: a Python Azure Function App that brings events and alerts into Microsoft Sentinel using the Log Analytics HTTP data collector
* Workbook: an Azure Workbook that helps visualize usage of the DocuSign organization and accounts, as well as alert history
* Analytics Rules: two analytics rules based on the pre-defined DocuSign Monitor alerts
* Hunting Query: an example query that can help identify anomalous activity based on IP addresses

## Requirements

This solution uses the DocuSign SDK for Python. Additional required libraries are found in `requirements.txt`

# Deployment

To deploy the solution, you must first pass the DocuSign integration [go-live requirements](https://developers.docusign.com/docs/esign-rest-api/go-live) in a developer account:

## Deploy for Developer Account

1. Register a DocuSign developer account
1. Follow [instructions](https://developers.docusign.com/platform/build-integration/) to create a new integration
1. Deploy the Azure Resource Manager (ARM) template:


[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fh0ffayyy%2FDocuSignMonitor-MicrosoftSentinel%2Fmaster%2Ftemplate.json)
[![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fh0ffayyy%2FDocuSignMonitor-MicrosoftSentinel%2Fmaster%2Ftemplate.json)


### Prepping RSA Key

The DocuSign API [JWT authentication method](https://developers.docusign.com/platform/auth/jwt/jwt-get-token/) requires an RSA keypair to sign the resulting JWT. I haven't found a good way to handle this in the ARM template with Azure Key Vault, so currently I manually upload the private key file to the Key Vault using Azure CLI (make sure you have a role that can modify secrets, such as the Key Vault Administrator role):

```bash
az keyvault secret set -f <private_key_file> --vault-name "<vault_name>" --name "<secret_name>" --subscription "<subscription_name>"
```

### Provide app consent

After deploying the ARM template, you'll need to provide consent as the user authenticating with our DocuSign JWT application. NOTE: You'll need to do this later for the production account as well.

Use the following URL format to sign in and approve the application:

```
https://account-d.docusign.com/oauth/auth?response_type=code&scope=impersonation signature user_read organization_read&client_id=<client_id>&redirect_uri=<redirect_uri>
```

## Pass Go-Live Review

After submitting at least 20 successful API requests, you can submit for a go-live review.


## Deploy to Production

After receiving the accepted go-live review, you can now update the function app for your production DocuSign account. 

You can either re-deploy the ARM template, or you can modify the existing function application settings. Ensure that the `ds_environment` variable is set to "PROD".

You'll also need to provide consent again for the production environment JWT application. Use the following URL format:

```
https://account.docusign.com/oauth/auth?response_type=code&scope=impersonation signature user_read organization_read&client_id=<client_id>&redirect_uri=<redirect_uri>
```
