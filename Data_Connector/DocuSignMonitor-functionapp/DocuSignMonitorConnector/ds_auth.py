import logging
from os import environ

import requests
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from docusign_admin import ApiClient
from docusign_monitor import ApiClient
from docusign_monitor.client.api_exception import ApiException

connection_string = environ['AzureWebJobsStorage']
ds_environment = environ["ds_environment"]
ds_client_secret = environ["ds_client_secret"]
ds_impersonated_user = environ["ds_impersonated_user"]
ds_integration_key = environ["ds_integration_key"]
ds_redirect_url = environ["ds_app_redirect"]
keyvault_name = environ['KVName']
privkey_name = environ['privkey_name']
SCOPE = [ "impersonation", "signature", "user_read", "organization_read" ]
if ds_environment == "DEV":
    ds_authorization_server = "account-d.docusign.com"
else:
    ds_authorization_server = "account.docusign.com"


class KeyManager:
    def __init__(self, vault_name, secret):
        self.credential = DefaultAzureCredential()
        self.vault_url = f"https://{keyvault_name}.vault.azure.net/"
        self.secret_client = SecretClient(self.vault_url, self.credential)
        self.secret_name = secret


    def get(self):
        try:
            return self.secret_client.get_secret(self.secret_name)
        except Exception as e:
            logging.error(e)
            return None


class DSClient:
    ds_app = None

    @classmethod
    def _init(cls):
        cls._jwt_auth()


    @classmethod
    def _jwt_auth(cls):
        """JSON Web Token authorization"""
        api_client = ApiClient()
        api_client.set_base_path(f"https://{ds_authorization_server}")

        use_scopes = SCOPE

        # Catch IO error
        try:
            private_key = cls._get_private_key()
            #private_key = cls._get_private_key().encode("ascii").decode("utf-8")
        except (OSError, IOError) as err:
            logging.error(err)

        try:
            logging.info("LOG: Requesting JWT...")
            cls.ds_app = api_client.request_jwt_user_token(
                client_id=ds_integration_key,
                user_id=ds_impersonated_user,
                oauth_host_name=ds_authorization_server,
                private_key_bytes=private_key,
                expires_in=4000,
                scopes=use_scopes
            )

        except ApiException as err:
            body = err.body.decode('utf8')
            logging.error(body)

            # Grant explicit consent for the application
            if "consent_required" in body or "invalid_grant" in body:
                consent_scopes = " ".join(use_scopes)
                redirect_uri = ds_redirect_url
                consent_url = f"https://{ds_authorization_server}/oauth/auth?response_type=code&" \
                              f"scope={consent_scopes}&client_id={ds_integration_key}&redirect_uri={redirect_uri}"
                logging.info(f"LOG: App consent required! {consent_url}")
            else:
                logging.error(err)


    @staticmethod
    def _get_private_key():

        try:
            key = KeyManager(keyvault_name, privkey_name)
            key_result = key.get()
            private_key = str.encode(key_result.value)

            if private_key == None:
                logging.error("No key retrieved from key vault!")
            else:
                logging.info(f"LOG: Got private key!")
        except Exception as e:
            logging.error(e)
            return

        return private_key


    @classmethod
    def get_user(cls, access_token):
        """Make request to the API to get the user information"""
        # Determine user, account_id, base_url by calling OAuth::getUserInfo
        # See https://developers.docusign.com/esign-rest-api/guides/authentication/user-info-endpoints
        if ds_environment == "DEV":
            url = f"https://account.docusign.com/oauth/userinfo"
        else:
            url = f"https://account-d.docusign.com/oauth/userinfo"
        auth = {"Authorization": "Bearer " + access_token}
        response = requests.get(url, headers=auth).json()

        return response


    @classmethod
    def get(cls, auth_type):
        if not cls.ds_app:
            cls._init(auth_type)
        return cls.ds_app


    @classmethod
    def login(cls):
        return cls._jwt_auth()


    @classmethod
    def get_token(cls):
        auth_type = "jwt"
        #resp = None
        resp = cls.get(auth_type).to_dict()

        return resp
