import base64
import datetime
import hashlib
import hmac
import json
import logging
from os import environ

import azure.functions as func
import requests

from .ds_auth import DSClient
from .state_manager import StateManager

chunksize = 10000
connection_string = environ['AzureWebJobsStorage']
customer_id = environ['WorkspaceID']
ds_environment = environ['ds_environment']
ds_account_id = environ["ds_account_id"]
ds_client_secret = environ["ds_client_secret"]
ds_integration_key = environ["ds_integration_key"]
ds_impersonated_user = environ["ds_impersonated_user"]
ds_redirect_url = environ["ds_app_redirect"]
privkey_name = environ['privkey_name']
SCOPE = [ "impersonation", "signature", "user_read", "organization_read" ]
shared_key = environ['WorkspaceKey']
table_name = "DocuSignMonitor"


class DSMon():

    def __init__(self):
        self.access_token = self.get_access_token()
        self.new_events = False
        self.user_list = []
        self.results_array = []
        self.state = StateManager(connection_string, "funcstatemarkerfile")


    def get_access_token(self):
        DSClient().login()
        resp = DSClient().get_token()

        access_token = resp["access_token"]
        refresh_token = resp["refresh_token"]
        token_expiry = datetime.datetime.utcnow() + datetime.timedelta(seconds=int(resp["expires_in"]))

        return access_token


    def check_cursor(self):
        """Checks last saved cursor"""
        previous_cursor = self.state.get()
        
        if previous_cursor is None:
            logging.info("LOG: No previous cursor, retrieving all logs")
            return False, None
        else:
            logging.info("LOG: Retrieving logs since previous cursor")
            return True, previous_cursor


    def get_monitor_stream(self):
        """ using requests for now, DS Monitor package throws error """
        headers = {"Authorization":f"Bearer {self.access_token}", "Accept":"application/json"}

        cursor_available, previous_cursor = self.check_cursor()

        if ds_environment == "DEV":
            ds_monitor_api_client_host = "lens-d.docusign.net"
        else:
            ds_monitor_api_client_host = "lens.docusign.net"

        try:
            if cursor_available == True:
                res = requests.get(
                    f"https://{ds_monitor_api_client_host}" \
                    f"/api/v2/datasets/monitor/stream?cursor={previous_cursor}", 
                    headers=headers
                )
            else:
                res = requests.get(
                    f"https://{ds_monitor_api_client_host}" \
                    "/api/v2/datasets/monitor/stream", 
                    headers=headers
                )
        except Exception as err:
            logging.error(f'Error retrieving events: {err}')
            return

        json_results = res.json()
        end_cursor = json_results['endCursor']

        if end_cursor == previous_cursor:
            logging.info(f"Cursor {end_cursor} is same as previous cursor! No new data.")
            self.new_events = False
        else:
            self.state.post(end_cursor)
            if len(json_results['data']) == 0:
                logging.info("LOG: No new events found in Monitor")
            else:
                self.new_events = True
                self.results_array = json_results['data']



    def get_org_id(self, headers):
        logging.info("LOG: Getting organization ID")

        if ds_environment == "DEV":
            ds_admin_api_client_host = "api-d.docusign.net/management"
        else:
            ds_admin_api_client_host = "api.docusign.net/management"

        try:
            res = requests.get(f"https://{ds_admin_api_client_host}/v2/organizations", headers=headers)
            json_results = res.json()

            logging.info(f"LOG: Found Org ID: {json_results['organizations'][0]['id']}")

            return json_results['organizations'][0]['id']

        except Exception as err:
            logging.err(f"Error getting Org ID: {err}")


    def get_user_data(self):
        headers = {
            "Authorization":f"Bearer {self.access_token}", 
            "Accept":"application/json"
        }
        combined_user_list = []

        ds_org_id = self.get_org_id(headers)

        logging.info("LOG: Retrieving users...")
        try:
            if ds_environment == "DEV":
                ds_admin_api_client_host = "api-d.docusign.net/management"
            else:
                ds_admin_api_client_host = "api.docusign.net/management"

            first_page = requests.get(
                f"https://{ds_admin_api_client_host}/Management/v2/organizations" \
                f"/{ds_org_id}/users?account_id={ds_account_id}&take=250", 
                headers=headers
            )

            page_results = first_page.json()
            combined_user_list.extend(page_results['users'])

            if page_results['paging']:
                while 'next' in page_results['paging'].keys():
                    next_url = page_results['paging']['next']
                    current_page = requests.get(f"{next_url}", headers=headers)
                    page_results = current_page.json()
                    combined_user_list.extend(page_results['users'])

                self.user_list = combined_user_list  
            else:
                self.user_list = page_results['users']
        except Exception as err:
            logging.error(f'Error retrieving users: {err}')


    def enrich_user_data(self):
        """ find users email based on userId and add to event message """

        for event in self.results_array:
            if "userId" in event.keys() and event["userId"] != '':
                user_id = event['userId']

                for user in self.user_list:
                    if user_id == user['id']:
                        event.update({'user_email': f'{user["email"]}'})   


class Sentinel:

    def __init__(self):
        self.table_name = table_name
        self.customer_id = customer_id
        self.shared_key = shared_key


    def build_signature(self, date, content_length, method, content_type, resource):
        x_headers = 'x-ms-date:' + date
        string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
        bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
        decoded_key = base64.b64decode(shared_key)
        encoded_hash = base64.b64encode(
            hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
        authorization = f"SharedKey {self.customer_id}:{encoded_hash}"

        return authorization


    # Build and send a request to the POST API
    def post_data(self, body):
        method = 'POST'
        content_type = 'application/json'
        resource = '/api/logs'
        rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        content_length = len(body)
        signature = self.build_signature(rfc1123date, content_length, method, content_type, resource)
        uri = f'https://{self.customer_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01'

        headers = {
            'content-type': content_type,
            'Authorization': signature,
            'Log-Type': self.table_name,
            'x-ms-date': rfc1123date
        }

        response = requests.post(uri,data=body, headers=headers)
        if (response.status_code >= 200 and response.status_code <= 299):
            print('Accepted')
            logging.info(f"{len(body)} events were processed")
        else:
            print(f"Response code: {response.status_code}")
            logging.warning(f"Response code: {response.status_code}")


def main(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.utcnow().replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')

    logging.info('Python timer trigger function ran at %s', utc_timestamp)

    DSM = DSMon()
    DSM.get_user_data()
    DSM.get_monitor_stream()
    DSM.enrich_user_data()

    if DSM.new_events == True:
        logging.info("LOG: New events found in Monitor")
        MSS = Sentinel()
        logging.info(f"Sending {len(DSM.results_array)} events to workspace...")
        MSS.post_data(json.dumps(DSM.results_array))
    else:
        logging.info("LOG: No new events in Monitor, ending run")
