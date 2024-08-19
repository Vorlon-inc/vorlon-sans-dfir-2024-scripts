import requests
import json
import pandas as pd
from oauthlib.oauth2 import WebApplicationClient
from requests_oauthlib import OAuth2Session
import os
from dotenv import load_dotenv

load_dotenv()
class AuthenticatorManager:
    def __init__(self, client_id, client_secret, authorize_url, token_url, redirect_uri):
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorize_url = authorize_url
        self.token_url = token_url
        self.redirect_uri = redirect_uri
        self.oauth_session = OAuth2Session(
            client_id=self.client_id, redirect_uri=self.redirect_uri)

    def get_authorization_url(self):
        authorization_url, state = self.oauth_session.authorization_url(
            self.authorize_url)
        print(
            f'Please go to this URL and authorize access: {authorization_url}')
        return authorization_url

    def fetch_token(self, authorization_response):
        self.oauth_session.fetch_token(self.token_url, authorization_response=authorization_response,
                                       client_id=self.client_id, client_secret=self.client_secret, include_client_id=True)

    def get_headers(self):
        return {
            "Authorization": f"Bearer {self.oauth_session.token['access_token']}",
            "Content-Type": "application/json"
        }

class APITokenManager:
    def __init__(self, headers):
        self.list_api_apps_endpoint = "https://api.hellosign.com/v3/api_app/list"
        self.create_api_app_endpoint = "https://api.hellosign.com/v3/api_app"
        self.delete_api_app_endpoint = "https://api.hellosign.com/v3/api_app"
        self.headers = headers

    def fetch_api_key_details(self):
        # Fetch API key/token details from the API endpoint
        response = requests.get(
            self.list_api_apps_endpoint, headers=self.headers)
        response.raise_for_status()
        return response.json()

    def parse_api_key_details(self, api_key_data):
        # Parse the API response and extract relevant details
        api_key_details = []
        for item in api_key_data:
            api_key_details.append(item)
        return api_key_details

    def create_token(self, payload):
        # Create a new API token for the specified user
        response = requests.post(
            self.create_api_app_endpoint, headers=self.headers, json=payload)
        response.raise_for_status()
        return response.json()

    def update_token(self, payload, client_id):
        # Create a new API token for the specified user
        response = requests.put(
            f"{self.create_api_app_endpoint}/{client_id}", headers=self.headers, json=payload)
        response.raise_for_status()
        return response.json()

    def delete_token(self, client_id):
        # Delete the specified API token
        response = requests.delete(
            f"{self.delete_api_app_endpoint}/{client_id}", headers=self.headers)
        response.raise_for_status()
        return response.json()

    def create_apps_from_json(self, json_file_path):
        properties_to_remove = ["client_id", "created_at",
                                "is_approved", "owner_account", "domain"]
        # Create apps from a JSON file after removing specified properties
        with open(json_file_path, 'r') as file:
            apps = json.load(file)

        for app in apps:
            # Rename the new app
            app["name"] = f"{app['name']} (New)"

            # Remove oauth properties
            if app["oauth"] is not None:
                app["oauth"].pop("secret", None)
                app["oauth"].pop("charges_users", None)

            # Remove specified properties
            for prop in properties_to_remove:
                # Check if prop is oauth and if so remove the callback_url
                app.pop(prop, None)  # Use pop with a default to avoid KeyError

            # Remove null properties
            app = {k: v for k, v in app.items() if v is not None}

            # Create the app (you can modify the payload as needed)
            # Use appropriate data for creation
            response = self.create_token(app)
            print(f"Created app with response: {response}")


class ReportGenerator:
    def save_to_csv(self, data, filename="./dropboxsign/api_key_details.csv"):
        """Save the parsed data to a CSV file."""
        df = pd.DataFrame(data)
        df.to_csv(filename, index=False)
        print(f"API key details have been saved to {filename}")

    def save_to_json(self, data, filename="./dropboxsign/api_key_details.json"):
        """Save the parsed data to a JSON file."""
        with open(filename, "w") as json_file:
            json.dump(data, json_file, indent=4)
        print(f"API key details have been saved to {filename}")


def main():
    # Configuration
    CLIENT_ID = os.getenv("CLIENT_ID")
    CLIENT_SECRET = os.getenv("CLIENT_SECRET")
    AUTHORIZE_URL = "https://app.hellosign.com/oauth/authorize"
    TOKEN_URL = "https://app.hellosign.com/oauth/token"
    REDIRECT_URI = "https://oauth.vorlon.io/redirect"

    # Authenticate and get headers
    authenticator = AuthenticatorManager(
        CLIENT_ID, CLIENT_SECRET, AUTHORIZE_URL, TOKEN_URL, REDIRECT_URI)

    # Instruct the user to visit the authorization URL and get the authorization response
    authorization_url = authenticator.get_authorization_url()
    authorization_response = input(
        'Enter the full callback URL after authorization: ')

    # Fetch the token using the authorization response
    authenticator.fetch_token(authorization_response)
    headers = authenticator.get_headers()

    # Fetch and parse API key details
    api_key_manager = APITokenManager(headers)
    api_key_data = api_key_manager.fetch_api_key_details()
    api_key_details = api_key_manager.parse_api_key_details(
        api_key_data.get("api_apps"))

    # Generate reports
    report_generator = ReportGenerator()
    report_generator.save_to_csv(api_key_details)
    report_generator.save_to_json(api_key_details)

    # Create new apps with the same permissions scopes amd props based on the apps report
    api_key_manager.create_apps_from_json("./dropboxsign/api_key_details.json")


if __name__ == "__main__":
    main()
