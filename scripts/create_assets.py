import requests
import json
import logging
from typing import Dict, Any
import os
import random
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class KeycloakAPI:
    def __init__(self, base_url: str, admin_user: str, admin_password: str):
        self.base_url = base_url.rstrip('/')
        self.admin_user = admin_user
        self.admin_password = admin_password
        self.token = None
        self.headers = {"Content-Type": "application/json"}
    def authenticate(self):
        """Authenticate with Keycloak and retrieve a token."""
        auth_url = f"{self.base_url}/realms/master/protocol/openid-connect/token"
        payload = {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": self.admin_user,
            "password": self.admin_password
        }
        response = requests.post(auth_url, data=payload)
        response.raise_for_status()
        self.token = response.json().get("access_token")
        self.headers["Authorization"] = f"Bearer {self.token}"
        logging.info("Authenticated successfully.")

    def request(self, method: str, endpoint: str, payload: Dict[str, Any] = None) -> str:
        """make a request to keycloak API"""
        url = f"{self.base_url}/{endpoint}"
        if method == "get":
            response = requests.get(url, headers=self.headers)
        elif method == "post":
            response = requests.post(url, headers=self.headers, json=payload)
        elif method == "put":
            response = requests.put(url, headers=self.headers, json=payload)
        elif method == "patch":
            response = requests.patch(url, headers=self.headers, json=payload)
        else:
            logging.error("no valid method provided")
        response.raise_for_status()
        logging.info(f"{method.upper()} request made to {url} (status code: {response.status_code})")
        return response

class KeycloakManager:
    def __init__(self, api: KeycloakAPI):
        self.api = api
        self.persisted_ids = {}

    def create_realm(self, realm_name: str):
        """Create a new realm."""
        payload = {"realm": realm_name, "enabled": True}
        realm = self.api.request("post", "admin/realms", payload)
        return realm

    def create_group(self, realm_name: str, group_name: str):
        """Create a new group in a realm."""
        payload = {"name": group_name}
        group = self.api.request("post", f"admin/realms/{realm_name}/groups", payload)
        return group

    def create_user(self, realm_name: str, username: str, email: str, password: str, first_name: str, last_name: str):
        """Create a new user in a realm."""
        payload = {
            "username": username,
            "email": email,
            "emailVerified": True,
            "firstName": first_name,
            "lastName": last_name,
            "enabled": True,
            "credentials": [{"type": "password", "value": password, "temporary": False}]
        }
        user = self.api.request("post", f"admin/realms/{realm_name}/users", payload)
        return user
    
    def create_client(self, client_type: str, client_id: str, web_app_url: str):
        """Create a new client."""
        if client_type == "oidc":
            payload = {
                        "clientId": client_id,
                        "redirectUris": [f"{web_app_url}/auth/realms/runai/broker/oidc/endpoint"],
                        "webOrigins": [f"{web_app_url}/*"],
                        "attributes": {
                            "login_theme": "genny",
                            "post.logout.redirect.uris": f"{web_app_url}/*"},
                        "standardFlowEnabled": True
                    }
        elif client_type == "saml":
            payload = {
                        "protocol": "saml",
                        "clientId": client_id,
                        "publicClient": True,
                        "authorizationServicesEnabled": False,
                        "serviceAccountsEnabled": False,
                        "implicitFlowEnabled": False,
                        "directAccessGrantsEnabled": True,
                        "standardFlowEnabled": True,
                        "frontchannelLogout": True,
                        "alwaysDisplayInConsole": False,
                        "rootUrl": web_app_url,
                        "baseUrl": web_app_url,
                        "adminUrl": "",
                        "redirectUris": [f"{web_app_url}/auth/realms/runai/broker/saml/endpoint"],
                        "attributes": {
                            "login_theme": "genny",
                            "saml_force_name_id_format": True,
                            "saml.client.signature": False,
                            "saml_name_id_format": "email",
                            "saml_idp_initiated_sso_url_name": "",
                            "saml_idp_initiated_sso_relay_state": "",
                            "post.logout.redirect.uris": f"{web_app_url}/*"
                        }
                    }
        else:
            logging.error("no valid client type provided.")
        client = self.api.request("post", f"admin/realms/{realm_name}/clients", payload)
        return client 

    def create_groups_mapper(self, client_uuid: str):
        """Create a mapper for groups in client."""
        payload = {
                    "protocol": "saml",
                    "protocolMapper": "saml-group-membership-mapper",
                    "name": "Groups Mapper",
                    "config": {
                        "attribute.name": "GROUPS",
                        "friendly.name": "",
                        "attribute.nameformat": "Basic",
                        "single": True,
                        "full.path": False
                    }
                }
        groups_mapper = self.api.request("post", f"admin/realms/{realm_name}/clients/{client_uuid}/protocol-mappers/models", payload)
        return groups_mapper

    def get_client_secret(self, client_uuid: str):
        """Get a client's secret."""
        response = self.api.request("get", f"admin/realms/{realm_name}/clients/{client_uuid}/client-secret")
        json_response = json.loads(response.content)
        secret = json_response["value"]
        return secret

    def add_users_to_group(self, user_uuid: str, group_uuid: str):
        """Add a user as a member of a group in the realm."""
        payload = {}
        response = self.api.request("put", f"admin/realms/{realm_name}/users/{user_uuid}/groups/{group_uuid}", payload)
        return response

class KeycloakData:
    def __init__(self, yaml_path: str):
        with open(yaml_path, 'r') as file:
            self.data = yaml.safe_load(file)

    def get_settings(self):
        return self.data['keycloak']['settings']

    def get_realm(self):
        return self.data['realm']['name']

    def get_groups(self):
        return self.data['groups']

    def get_users(self):
        return self.data['users']

    def get_clients(self):
        return self.data['clients']

if __name__ == "__main__":
    # Initialize data, API and Manager classes:
    yaml_path = os.getenv("KEYCLOAK_DATA_YAML_PATH")
    keycloak_data = KeycloakData(yaml_path)
    base_url = keycloak_data.get_settings()["url"]
    admin_user = keycloak_data.get_settings()["admin"]["username"]
    admin_pass = keycloak_data.get_settings()["admin"]["password"]

    keycloak_api = KeycloakAPI(base_url, admin_user, admin_pass)
    keycloak_manager = KeycloakManager(keycloak_api)

    try:
        # Authenticate
        keycloak_api.authenticate()

        # Create realm
        realm_name = keycloak_data.get_realm()
        realm = keycloak_manager.create_realm(realm_name)
        realm_url = realm.headers["Location"]
        logging.info(f"Realm created: '{realm_url}'")

        # create clients
        for client in keycloak_data.get_clients():
            client_type = client["type"]
            client_id = client["id"]
            web_app_url = client["webAppURL"]
            client = keycloak_manager.create_client(client_type, client_id, web_app_url)
            client_uuid = client.headers["Location"].split("/")[-1]
            client_url = client.headers["Location"]
            logging.info(f"{client_type.upper()} Client '{client_id}' created (UUID: '{client_uuid}')")
            if client_type == "saml":
                client_metadata_url = f"{keycloak_api.base_url}/realms/{realm_name}/protocol/saml/descriptor"
                logging.info(f"{client_type.upper()} Client '{client_id}' created (Metadata URL: '{client_metadata_url}')")
                cgm = keycloak_manager.create_groups_mapper(client_uuid)
                logging.info(f"Groups mapper added to {client_type.upper()} Client '{client_id}' (Status: {cgm.ok})")
            elif client_type == "oidc":
                client_secret = keycloak_manager.get_client_secret(client_uuid)
                logging.info(f"{client_type.upper()} Client '{client_id}' created (UUID: '{client_uuid}')")
                logging.info(f"{client_type.upper()} Client '{client_id}' created (Secret: '{client_secret}')")

        # create users and groups
        for user in keycloak_data.get_users():
            username = user["username"]
            email = user["email"]
            password = user["password"]
            first_name = user["first-name"]
            last_name = user["last-name"]
            group_name = user["group"]

            user = keycloak_manager.create_user(realm_name, username, email, password, first_name, last_name)
            user_uuid = user.headers["Location"].split("/")[-1]
            user_url = user.headers["Location"]
            logging.info(f"User '{email}' created (UUID: '{user_uuid}')")

            group = keycloak_manager.create_group(realm_name, group_name)
            group_uuid = group.headers["Location"].split("/")[-1]
            group_url = group.headers["Location"]
            logging.info(f"Group '{group_name}' created (UUID: '{group_uuid}')")
            u2g = keycloak_manager.add_users_to_group(user_uuid, group_uuid)
            logging.info(f"User '{email}' added to group '{group_name}' (Status: {str(u2g.ok)})")
        
        logging.info("done 1")
        logging.info("done 2")
    except requests.exceptions.RequestException as e:
        logging.error(f"API error: {e}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
