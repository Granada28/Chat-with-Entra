"""
Stage 1 - Entra ID Data Retrieval
This script connects to your Entra tenant via the Microsoft Graph API
and pulls security-relevant data: users, role assignments, Conditional
Access policies, and service principals.
"""

import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

# Read credentials from environment variables
TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

# Microsoft Graph API base URL
GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def get_access_token():
    """
    Authenticate using OAuth2 Client Credentials flow.
    This gets a token that represents the APPLICATION itself (not a user).
    The token is then used in all subsequent API calls.
    """
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "https://graph.microsoft.com/.default"
    }
    response = requests.post(url, data=data)
    response.raise_for_status()
    return response.json()["access_token"]


def graph_get(token, endpoint, params=None):
    """
    Helper function to make GET requests to the Microsoft Graph API.
    Handles pagination automatically - some endpoints return results
    in pages, and this function follows the @odata.nextLink to get all results.
    """
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{GRAPH_BASE}{endpoint}"
    all_results = []

    while url:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        all_results.extend(data.get("value", []))
        # If there are more pages of results, follow the nextLink
        url = data.get("@odata.nextLink")
        params = None  # nextLink already contains query parameters

    return all_results


def get_users(token):
    """
    Retrieve all users with security-relevant properties.
    We select specific fields to get useful data without downloading everything.
    """
    print("[*] Fetching users...")
    users = graph_get(
        token,
        "/users",
        params={
            "$select": "id,displayName,userPrincipalName,userType,accountEnabled,"
                       "createdDateTime",
            "$top": "999"
        }
    )
    print(f"    Found {len(users)} users")
    return users


def get_directory_roles(token):
    """
    Retrieve activated directory roles and their members.
    This tells you WHO has which admin role (e.g., Global Administrator).
    """
    print("[*] Fetching directory role assignments...")
    roles = graph_get(token, "/directoryRoles")
    
    role_assignments = []
    for role in roles:
        members = graph_get(token, f"/directoryRoles/{role['id']}/members")
        role_assignments.append({
            "roleName": role["displayName"],
            "roleId": role["id"],
            "members": [
                {
                    "displayName": m.get("displayName", "N/A"),
                    "userPrincipalName": m.get("userPrincipalName", "N/A"),
                    "type": m.get("@odata.type", "unknown")
                }
                for m in members
            ]
        })
    
    print(f"    Found {len(role_assignments)} active roles")
    return role_assignments


def get_conditional_access_policies(token):
    """
    Retrieve all Conditional Access policies.
    These are the main security rules that control how and when users
    can access resources (e.g., require MFA, block legacy auth).
    """
    print("[*] Fetching Conditional Access policies...")
    policies = graph_get(token, "/identity/conditionalAccess/policies")
    print(f"    Found {len(policies)} policies")
    return policies


def get_service_principals(token):
    """
    Retrieve service principals (app identities in your tenant).
    Service principals with high permissions are a common attack vector.
    """
    print("[*] Fetching service principals...")
    sps = graph_get(
        token,
        "/servicePrincipals",
        params={
            "$select": "id,displayName,appId,servicePrincipalType,"
                       "appRoleAssignmentRequired",
            "$top": "999"
        }
    )
    print(f"    Found {len(sps)} service principals")
    return sps


def main():
    """Main function that pulls all data and saves it to a JSON file."""
    print("=" * 60)
    print("Entra ID Data Collection")
    print("=" * 60)

    token = get_access_token()
    print("[+] Authentication successful\n")

    # Collect all security-relevant data
    tenant_data = {
        "users": get_users(token),
        "role_assignments": get_directory_roles(token),
        "conditional_access_policies": get_conditional_access_policies(token),
        "service_principals": get_service_principals(token)
    }

    # Save the data to a JSON file for later use by the agent
    output_file = "tenant_data.json"
    with open(output_file, "w") as f:
        json.dump(tenant_data, f, indent=2, default=str)

    print(f"\n[+] Data saved to {output_file}")
    print(f"    Users: {len(tenant_data['users'])}")
    print(f"    Roles: {len(tenant_data['role_assignments'])}")
    print(f"    CA Policies: {len(tenant_data['conditional_access_policies'])}")
    print(f"    Service Principals: {len(tenant_data['service_principals'])}")


if __name__ == "__main__":
    main()
