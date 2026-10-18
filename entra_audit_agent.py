"""
Stage 3 - Entra ID Security Audit Agent (Production-Hardened)
Actively audits a Microsoft Entra ID tenant for common security misconfigurations
using Microsoft Graph API and Azure OpenAI function calling.
"""

import os
import sys
import time
import json
import logging
from typing import Any, Dict, List, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv
from openai import AzureOpenAI

# Configure logging
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

load_dotenv()

# ---- Configuration & Startup Validation ----

REQUIRED_ENV_VARS = [
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_DEPLOYMENT",
    "TENANT_ID",
    "CLIENT_ID",
    "CLIENT_SECRET",
]

missing_vars = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]
if missing_vars:
    sys.exit(f"Error: Missing required environment variables: {', '.join(missing_vars)}")

ai_client = AzureOpenAI(
    azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
    api_key=os.environ["AZURE_OPENAI_API_KEY"],
    api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-12-01-preview"),
)
DEPLOYMENT = os.environ["AZURE_OPENAI_DEPLOYMENT"]

TENANT_ID = os.environ["TENANT_ID"]
CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
MS_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"


# ---- HTTP Session & Token Caching ----

class GraphClient:
    """Manages Microsoft Graph authentication, token caching, and resilient HTTP requests."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0

        # Configure a persistent HTTP session with automatic retries for transient errors and 429s
        self.session = requests.Session()
        retries = Retry(
            total=4,
            backoff_factor=1.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
            respect_retry_after_header=True,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retries))

    def get_access_token(self) -> str:
        """Fetch an OAuth2 access token, reusing the cached token until 60s before expiry."""
        now = time.time()
        if self._token and now < (self._token_expiry - 60):
            return self._token

        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://graph.microsoft.com/.default",
        }
        resp = self.session.post(url, data=data, timeout=15)
        resp.raise_for_status()
        payload = resp.json()

        self._token = payload["access_token"]
        self._token_expiry = now + int(payload.get("expires_in", 3599))
        return self._token

    def get_paginated(self, endpoint: str, params: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """Make a GET request to Microsoft Graph and automatically follow @odata.nextLink."""
        token = self.get_access_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "ConsistencyLevel": "eventual",
        }
        url: Optional[str] = f"{GRAPH_BASE}{endpoint}"
        all_results: List[Dict[str, Any]] = []

        while url:
            resp = self.session.get(url, headers=headers, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            all_results.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            # Clear params after the first request because nextLink already embeds them
            params = None

        return all_results


graph = GraphClient(TENANT_ID, CLIENT_ID, CLIENT_SECRET)


# ---- Audit Tool Functions ----

def audit_admin_accounts() -> str:
    """
    AUDIT CHECK: Analyze directory role assignments for security issues.
    Looks for: excessive Global Admins (>4), service principals in admin roles,
    and external/guest users assigned to admin roles.
    """
    try:
        # Use $expand=members to avoid the N+1 query problem
        roles = graph.get_paginated("/directoryRoles", params={"$expand": "members"})
    except requests.HTTPError as e:
        return json.dumps([{"severity": "ERROR", "finding": f"Failed to query directoryRoles: {e}"}])

    findings: List[Dict[str, str]] = []

    for role in roles:
        role_name = role.get("displayName", "Unknown Role")
        members = role.get("members", [])

        # Check 1: Excessive Global Administrators
        if role_name == "Global Administrator" and len(members) > 4:
            findings.append({
                "severity": "HIGH",
                "finding": f"Too many Global Administrators: {len(members)} found",
                "detail": (
                    "Microsoft recommends between 2 and 4 Global Administrators. "
                    "Excessive full-control accounts expand the blast radius of credential compromise."
                ),
                "recommendation": (
                    "Transition users who do not need tenant-wide control to least-privilege roles "
                    "(e.g., Security Administrator, User Administrator) or use Privileged Identity Management (PIM) "
                    "for just-in-time activation."
                ),
            })

        for m in members:
            odata_type = m.get("@odata.type", "")
            display_name = m.get("displayName", "Unnamed Object")
            upn = m.get("userPrincipalName", "")

            # Check 2: Service Principals in ANY privileged role (especially Global Admin)
            if "#microsoft.graph.servicePrincipal" in odata_type:
                sev = "CRITICAL" if role_name == "Global Administrator" else "HIGH"
                findings.append({
                    "severity": sev,
                    "finding": f"Service principal '{display_name}' holds the '{role_name}' directory role",
                    "detail": (
                        "Directory roles granted to service principals bypass interactive sign-in controls "
                        "and often carry broad tenant permissions."
                    ),
                    "recommendation": (
                        f"Remove '{display_name}' from '{role_name}' and replace with granular "
                        "Microsoft Graph application permissions where strictly required."
                    ),
                })

            # Check 3: Guest users in admin roles
            # Note: $expand=members does not always return userType, so we check both userType and #EXT# UPNs
            is_guest = m.get("userType") == "Guest" or "#EXT#@" in upn
            if is_guest:
                findings.append({
                    "severity": "HIGH",
                    "finding": f"Guest user '{display_name}' ({upn}) holds the '{role_name}' role",
                    "detail": (
                        "External identities are managed outside your tenant's primary identity lifecycle "
                        "and device compliance boundaries."
                    ),
                    "recommendation": (
                        f"Remove '{display_name}' from the '{role_name}' role immediately. "
                        "If administrative access is required for a partner, provision a dedicated member account."
                    ),
                })

    if not findings:
        findings.append({
            "severity": "INFO",
            "finding": "Admin role assignments appear healthy",
            "detail": "Global Admin count is <= 4, and no guest users or service principals hold directory roles.",
        })

    return json.dumps(findings, indent=2)


def audit_conditional_access() -> str:
    """
    AUDIT CHECK: Analyze Conditional Access policies for common security gaps.
    Looks for: missing MFA enforcement, missing legacy auth block,
    disabled or report-only policies.
    """
    try:
        policies = graph.get_paginated("/identity/conditionalAccess/policies")
    except requests.HTTPError as e:
        return json.dumps([{"severity": "ERROR", "finding": f"Failed to query Conditional Access policies: {e}"}])

    findings: List[Dict[str, str]] = []

    if not policies:
        return json.dumps([{
            "severity": "CRITICAL",
            "finding": "No Conditional Access policies configured",
            "detail": "The tenant has zero Conditional Access rules enforcing MFA or blocking legacy authentication.",
            "recommendation": "Deploy baseline Conditional Access policies requiring MFA and blocking legacy protocols.",
        }], indent=2)

    enabled_policies = [p for p in policies if p.get("state") == "enabled"]
    report_only_policies = [p for p in policies if p.get("state") == "enabledForReportingButNotEnforced"]
    disabled_policies = [p for p in policies if p.get("state") == "disabled"]

    if disabled_policies:
        names = [p.get("displayName", "Unnamed") for p in disabled_policies]
        findings.append({
            "severity": "LOW",
            "finding": f"{len(disabled_policies)} Conditional Access policy/policies are disabled",
            "detail": f"Disabled policies: {', '.join(names)}.",
            "recommendation": "Enable needed policies or delete obsolete ones to keep policy management clean.",
        })

    if report_only_policies:
        names = [p.get("displayName", "Unnamed") for p in report_only_policies]
        findings.append({
            "severity": "MEDIUM",
            "finding": f"{len(report_only_policies)} Conditional Access policy/policies are stuck in Report-Only mode",
            "detail": f"Report-only policies log results but do not enforce controls: {', '.join(names)}.",
            "recommendation": "Verify sign-in logs for unexpected blocks and switch validated policies to 'On'.",
        })

    mfa_policy_found = False
    legacy_block_found = False

    for p in enabled_policies:
        # Use `or {}` because Graph API explicitly returns `"grantControls": null` when unconfigured
        controls = p.get("grantControls") or {}
        built_in = controls.get("builtInControls") or []
        auth_strength = controls.get("authenticationStrength")

        if "mfa" in built_in or auth_strength:
            mfa_policy_found = True

        conditions = p.get("conditions") or {}
        client_apps = conditions.get("clientAppTypes") or []
        if ("exchangeActiveSync" in client_apps or "other" in client_apps) and "block" in built_in:
            legacy_block_found = True

    if not mfa_policy_found:
        findings.append({
            "severity": "CRITICAL",
            "finding": "No active Conditional Access policy enforces MFA",
            "detail": "No enabled policy requires multi-factor authentication or authentication strength.",
            "recommendation": "Create and enable a Conditional Access policy requiring Phishing-Resistant MFA or standard MFA for all users.",
        })

    if not legacy_block_found:
        findings.append({
            "severity": "HIGH",
            "finding": "No active Conditional Access policy blocks legacy authentication",
            "detail": "Legacy protocols (Exchange ActiveSync, POP, IMAP, SMTP basic auth) cannot enforce MFA.",
            "recommendation": "Create a Conditional Access policy targeting 'Exchange ActiveSync' and 'Other' client apps with the 'Block' grant control.",
        })

    if not findings:
        findings.append({
            "severity": "INFO",
            "finding": "Conditional Access baseline checks passed",
            "detail": f"{len(enabled_policies)} active policies verified, including MFA and legacy auth controls.",
        })

    return json.dumps(findings, indent=2)


def audit_service_principals() -> str:
    """
    AUDIT CHECK: Look for service principals granted high-privilege Microsoft Graph application permissions.
    Queries assignments directly on the Microsoft Graph resource Service Principal to avoid N+1 queries.
    """
    findings: List[Dict[str, str]] = []

    # High-risk Microsoft Graph Application Permissions (App Role IDs)
    dangerous_permissions = {
        "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
        "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
        "19dbc75e-c2e2-444c-a770-ec596d83d9ad": "Directory.ReadWrite.All",
    }

    try:
        # Step 1: Locate the Microsoft Graph service principal in this tenant
        graph_sps = graph.get_paginated(
            "/servicePrincipals",
            params={"$filter": f"appId eq '{MS_GRAPH_APP_ID}'", "$select": "id,displayName"},
        )
        if not graph_sps:
            return json.dumps([{"severity": "ERROR", "finding": "Could not locate Microsoft Graph service principal."}])

        graph_sp_id = graph_sps[0]["id"]

        # Step 2: Fetch all appRoleAssignedTo on Microsoft Graph in a single paginated stream
        # This replaces making 500+ individual HTTP calls for every SP in the tenant!
        assignments = graph.get_paginated(f"/servicePrincipals/{graph_sp_id}/appRoleAssignedTo")
    except requests.HTTPError as e:
        return json.dumps([{"severity": "ERROR", "finding": f"Failed to audit service principals: {e}"}])

    # Group dangerous permissions by principal display name
    sp_Perms: Dict[str, List[str]] = {}
    for assignment in assignments:
        role_id = assignment.get("appRoleId", "")
        if role_id in dangerous_permissions:
            principal_name = assignment.get("principalDisplayName", "Unknown Service Principal")
            perm_name = dangerous_permissions[role_id]
            sp_Perms.setdefault(principal_name, []).append(perm_name)

    for sp_name, perms in sp_Perms.items():
        unique_perms = sorted(set(perms))
        findings.append({
            "severity": "HIGH",
            "finding": f"Service principal '{sp_name}' has high-privilege Graph permissions",
            "detail": (
                f"Granted application permissions: {', '.join(unique_perms)}. "
                "Compromise of this workload identity allows tenant-wide privilege escalation."
            ),
            "recommendation": (
                f"Audit '{sp_name}' credentials (prefer Managed Identities or federated credentials over client secrets) "
                "and downgrade permissions to least privilege."
            ),
        })

    if not findings:
        findings.append({
            "severity": "INFO",
            "finding": "No service principals found with critical privilege-escalation Graph permissions",
            "detail": "Checked all assignments to Microsoft Graph against known dangerous AppRole IDs.",
        })

    return json.dumps(findings, indent=2)


def audit_guest_users() -> str:
    """
    AUDIT CHECK: Review guest user accounts for governance risks.
    """
    try:
        guests = graph.get_paginated(
            "/users",
            params={
                "$filter": "userType eq 'Guest'",
                "$select": "id,displayName,userPrincipalName,createdDateTime,accountEnabled,externalUserState",
            },
        )
    except requests.HTTPError as e:
        return json.dumps([{"severity": "ERROR", "finding": f"Failed to query guest users: {e}"}])

    findings: List[Dict[str, str]] = []

    if len(guests) > 50:
        findings.append({
            "severity": "MEDIUM",
            "finding": f"High volume of guest users: {len(guests)} accounts",
            "detail": "Large numbers of external identities increase exposure if not governed by periodic access reviews.",
            "recommendation": "Configure Entra ID Governance Access Reviews to automatically expire stale guest accounts.",
        })

    disabled_guests = [g for g in guests if not g.get("accountEnabled", True)]
    if disabled_guests:
        findings.append({
            "severity": "LOW",
            "finding": f"{len(disabled_guests)} disabled guest account(s) remain in the directory",
            "detail": "Disabled external accounts indicate departed collaborators whose objects were never purged.",
            "recommendation": "Delete disabled guest user objects after retention requirements are met.",
        })

    pending_guests = [g for g in guests if g.get("externalUserState") == "PendingAcceptance"]
    if pending_guests:
        findings.append({
            "severity": "LOW",
            "finding": f"{len(pending_guests)} guest user invitation(s) are still PendingAcceptance",
            "detail": "Unredeemed invitations may represent abandoned access requests.",
            "recommendation": "Revoke stale unredeemed guest invitations.",
        })

    if not findings:
        msg = f"{len(guests)} guest user(s) found with no immediate hygiene issues." if guests else "No guest users exist in the tenant."
        findings.append({
            "severity": "INFO",
            "finding": "Guest user hygiene looks clean",
            "detail": msg,
        })

    return json.dumps(findings, indent=2)


def run_full_audit() -> str:
    """Run all security audit checks and return a consolidated JSON report."""
    report = {
        "admin_accounts": json.loads(audit_admin_accounts()),
        "conditional_access": json.loads(audit_conditional_access()),
        "service_principals": json.loads(audit_service_principals()),
        "guest_users": json.loads(audit_guest_users()),
    }
    return json.dumps(report, indent=2)


# ---- Tool Definitions ----

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "audit_admin_accounts",
            "description": "Audit directory admin role assignments for excessive Global Admins, service principals in admin roles, or guest admins.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "audit_conditional_access",
            "description": "Audit Conditional Access policies for missing MFA, unblocked legacy authentication, disabled policies, and report-only policies.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "audit_service_principals",
            "description": "Audit service principals for dangerous Microsoft Graph application permissions (e.g., RoleManagement.ReadWrite.Directory).",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "audit_guest_users",
            "description": "Audit external guest user accounts for excessive volume, disabled accounts, or pending invitations.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_full_audit",
            "description": "Run a comprehensive security audit across admin accounts, Conditional Access, service principals, and guest users.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
]

AVAILABLE_FUNCTIONS = {
    "audit_admin_accounts": audit_admin_accounts,
    "audit_conditional_access": audit_conditional_access,
    "audit_service_principals": audit_service_principals,
    "audit_guest_users": audit_guest_users,
    "run_full_audit": run_full_audit,
}

SYSTEM_PROMPT = """You are an Entra ID Security Audit Agent. You have tools that query
a live Microsoft Entra ID tenant and perform automated security checks.

YOUR CAPABILITIES:
- Audit admin role assignments for misconfigurations
- Check Conditional Access policies for common gaps
- Detect overprivileged service principals
- Review guest user accounts for risks
- Run a full comprehensive security audit

YOUR BEHAVIOR:
- When asked to audit or check security, ALWAYS invoke the appropriate tool to inspect real tenant data.
- Present findings ordered by severity: CRITICAL > HIGH > MEDIUM > LOW > INFO (and report ERRORs clearly if permissions are missing).
- For each finding, explain: WHAT the issue is, WHY it is dangerous, and HOW to remediate it.
- Reference specific object names (e.g., service principal names, policy names, UPNs) returned by the tools.
- When running a full audit, provide an executive summary of key risks at the top before diving into details.
"""


def run_agent() -> None:
    """Main interactive loop for the Entra ID Security Audit Agent."""
    messages: List[Any] = [{"role": "system", "content": SYSTEM_PROMPT}]

    print("Entra ID Security Audit Agent (type 'quit' to exit)")
    print("=" * 55)
    print("Try: 'Run a full security audit' or")
    print("     'Check if our Conditional Access policies are secure'")
    print("=" * 55)

    while True:
        try:
            user_input = input("\nYou: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting...")
            break

        if user_input.lower() in ("quit", "exit"):
            break
        if not user_input:
            continue

        messages.append({"role": "user", "content": user_input})

        try:
            response = ai_client.chat.completions.create(
                model=DEPLOYMENT,
                messages=messages,
                tools=TOOLS,
                tool_choice="auto",
            )
            response_message = response.choices[0].message

            while response_message.tool_calls:
                messages.append(response_message)

                for tool_call in response_message.tool_calls:
                    fn_name = tool_call.function.name
                    print(f"  [Running audit: {fn_name}...]")

                    fn = AVAILABLE_FUNCTIONS.get(fn_name)
                    if fn:
                        result = fn()
                    else:
                        result = json.dumps({"error": f"Unknown tool: {fn_name}"})

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": result,
                    })

                response = ai_client.chat.completions.create(
                    model=DEPLOYMENT,
                    messages=messages,
                    tools=TOOLS,
                    tool_choice="auto",
                )
                response_message = response.choices[0].message

            print(f"\nAgent: {response_message.content}")
            messages.append(response_message)

        except Exception as e:
            logger.error(f"Error communicating with Azure OpenAI: {e}")


if __name__ == "__main__":
    run_agent()