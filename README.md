# Chat-with-Entra

Interactive Azure OpenAI agent for auditing a Microsoft Entra ID tenant through
Microsoft Graph. The agent can check administrator roles, Conditional Access
policies, service principals, and guest users.

## Prerequisites

- Python 3.9 or newer
- An Azure OpenAI resource with a chat-capable model deployment
- A Microsoft Entra app registration with a client secret
- An account that can grant admin consent for the required Microsoft Graph
	application permissions

## 1. Create a virtual environment

Run these commands from this directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

## 2. Configure Entra permissions

Create an app registration in **Microsoft Entra ID > App registrations** and
create a client secret. Add these **Microsoft Graph > Application permissions**
and grant admin consent:

- `User.Read.All`                       Read all users' full profiles
- `Directory.Read.All`                  Read directory data
- `RoleManagement.Read.Directory`       Read all directory RBAC settings
- `Policy.Read.All`                     Policy.Read.All
- `Application.Read.All`                Read all applications
- `DelegatedPermissionGrant.Read.All`   Read all delegated permission grants

The audit uses the OAuth2 client-credentials flow. Keep the client secret
private and do not commit it to source control.

## 3. Configure environment variables

Create a file named `.env` in this directory:

```dotenv
AZURE_OPENAI_ENDPOINT=https://<resource-name>.openai.azure.com/
AZURE_OPENAI_API_KEY=<azure-openai-api-key>
AZURE_OPENAI_DEPLOYMENT=<deployment-name>
AZURE_OPENAI_API_VERSION=2024-12-01-preview

TENANT_ID=<directory-tenant-id>
CLIENT_ID=<app-registration-client-id>
CLIENT_SECRET=<client-secret>
```

`AZURE_OPENAI_DEPLOYMENT` is the deployment name configured in Azure OpenAI,
not necessarily the underlying model name. The API version defaults to
`2024-12-01-preview` in the current script.

## 4. Run the agent

```bash
source .venv/bin/activate
python entra_audit_agent.py
```

Try prompts such as:

- `Run a full security audit`
- `Check if our Conditional Access policies are secure`
- `Audit administrator accounts`

Enter `quit` or `exit` to stop the agent.

## Other scripts

- `entra_data.py` collects tenant data and writes `tenant_data.json`.
- `entra_agent.py` provides live Graph question answering.
- `chat_basic.py`, `chat_system_prompt.py`, and `agent_basic.py` are smaller
	Azure OpenAI examples.

Run any script from this directory after activating the virtual environment:

```bash
python entra_data.py
python entra_agent.py
```

## Troubleshooting

- `ModuleNotFoundError`: activate `.venv` and run `python -m pip install -r requirements.txt`.
- `401` or `invalid_client`: verify `TENANT_ID`, `CLIENT_ID`, and
	`CLIENT_SECRET`; make sure the secret has not expired.
- Graph `403`: grant the permissions above and select **Grant admin consent**.
- Azure OpenAI `404`: check the endpoint and use the exact deployment name.
- Azure OpenAI `401`: verify the API key and that the resource is reachable.

The scripts query live tenant data. Review findings before making changes in
your tenant, and use a least-privilege app registration where possible.
