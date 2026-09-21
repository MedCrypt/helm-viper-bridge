# Helm API Server

FastAPI server bridging Helm (vulnerability management) and Viper, with Google SSO
self-serve API key generation.

---

## Project Structure

```
helm-viper-bridge/
├── fastapi_server.py        # Main server
├── models.py                # Pydantic request/response models
├── config.py                # All configuration (edit this)  ⚠️ gitignored
├── config.example.py        # Config template for new setups
├── auth_sso.py              # Google OAuth / SSO logic
├── requirements.txt         # Python dependencies
├── .env.example             # Environment variable template
├── .env                     # Your populated .env  ⚠️ gitignored
│
├── helm_*.py                # Helm business logic modules
├── helm_viper_device_groups.py
│
├── api_keys.txt             # Internal API keys (full access)  ⚠️ gitignored
├── external_api_keys.txt    # External API keys (read-only)    ⚠️ gitignored
├── viper_app_key.txt        # Shared Viper app key             ⚠️ gitignored
├── whitelisted_emails.example.txt  # Approved external emails template
│
├── start_server.sh          # Start FastAPI server
├── stop_server.sh           # Stop FastAPI server
├── start_tunnel.sh          # Start Cloudflare tunnel
├── stop_tunnel.sh           # Stop Cloudflare tunnel
├── check_status.sh          # Check server + tunnel status
├── restart_all.sh           # Restart both
│
├── medcrypt-helm-api-sdk/   # Helm SDK (protobuf client)
└── venv/                    # Python virtual environment (gitignored)
```

---

## Secrets & Credentials

Secrets are supplied as **environment variables** at startup. They are read **once at startup** — to pick up a rotated credential, restart the server.

Use whatever secret manager you prefer, or a plain `.env` file. The bundled
`start_server.sh` wraps startup in 1Password's `op run`; adapt it to your own
tooling if you use something else.

| Secret | Env var | Loaded |
|--------|---------|--------|
| Helm client ID | `HELM_CLIENT_ID` | Startup (env) |
| Helm client secret | `HELM_CLIENT_SECRET` | Startup (env) |
| Viper API key | `VIPER_API_KEY` | Startup (env) |
| Google OAuth client ID | `GOOGLE_CLIENT_ID` | Startup (env) |
| Google OAuth client secret | `GOOGLE_CLIENT_SECRET` | Startup (env) |
| Session secret key | `SESSION_SECRET_KEY` | Startup (env) |
| Internal API keys | `api_keys.txt` | Every request (disk) |
| External API keys | `external_api_keys.txt` | Every request (disk) |
| Viper app key | `viper_app_key.txt` | Every request (disk) |

Copy `.env.example` to `.env` and fill in your values. `.env` is gitignored.

---

## Setup

### 1. Prerequisites

- Python 3.12+
- A way to supply environment variables at startup (a `.env` file, or a secret
  manager such as the [1Password CLI](https://developer.1password.com/docs/cli/get-started/))

### 2. Clone the Repo

```bash
git clone <repo-url>
cd helm-viper-bridge
```

### 3. Configuration Files

These are gitignored and managed on disk by the app:

| File | How to get it |
|------|---------------|
| `config.py` | `cp config.example.py config.py` then fill in non-secret values |
| `viper_app_key.txt` | Get from a team member — this is the shared Viper app key |
| `api_keys.txt` | Can start empty — users generate their own keys via SSO |
| `external_api_keys.txt` | Can start empty — users generate their own keys via SSO |

### 4. Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` installs:
- `fastapi`, `uvicorn`, `pydantic` — API server
- `requests`, `httpx` — HTTP clients
- `authlib`, `itsdangerous` — Google OAuth / sessions
- `protobuf==3.20.3` — Helm SDK serialization

### 5. Configure `config.py`

Open `config.py` and verify or update the non-secret values:

```python
# Helm API target
HELM_API_URL        = "https://helm.coffee-sandbox.medcrypt.co/api-gw/v1"
HELM_WORKSPACE_NAME = "YOUR_WORKSPACE_NAME"
HELM_PRODUCT_NAME   = "YOUR_PRODUCT_NAME"

# OAuth redirect URI
OAUTH_REDIRECT_URI = "https://helm-api.com/auth/callback"

# Internal email domains (auto-get internal keys via SSO)
INTERNAL_EMAIL_DOMAINS = ["medcrypt.com", "medcrypt.co"]
```

Secrets (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `SESSION_SECRET_KEY`) are read from the environment — do not set them here.

---

## Google Auth Setup

Users visit `https://helm-api.com/auth/login` to log in with Google and receive an API key. Keys are written to disk and picked up on every request — no restart needed when new users sign in.

### Access Rules

| Email | Key type |
|-------|----------|
| `*@medcrypt.com` or `*@medcrypt.co` | Internal (full access) |
| Email in `whitelisted_emails.txt` | External (read-only) |
| All others | Access denied |

### Step 1 — Google Cloud Console

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Create or select a project
3. **APIs & Services → Credentials → Create Credentials → OAuth client ID**
4. Application type: **Web application**
5. Authorized JavaScript origins: `https://helm-api.com`
6. Authorized redirect URIs: `https://helm-api.com/auth/callback`
7. Save the **Client ID** and **Client Secret**

### Step 2 — Provide the OAuth Credentials

Expose the client ID and secret to the server as environment variables:

```bash
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
```

### Step 3 — Add External Users

Edit `whitelisted_emails.txt` (one email per line, `#` for comments). Changes take effect immediately — no restart needed.

### Step 4 — User Flow

1. User visits `https://helm-api.com/auth/login`
2. Clicks **Login with Google**
3. Authenticates with their Google account
4. Receives their personal API key
5. Can click **Regenerate Key** to invalidate and replace it

External users can also view and regenerate the shared **Viper app key** from the same page.

---

## Start / Stop

All scripts run from the project root.

### Start

```bash
./start_server.sh    # FastAPI server (background, logs → server.log)
```


### Stop

```bash
./stop_server.sh
```

### Restart

```bash
./restart_all.sh
```

### Status

```bash
./check_status.sh
```

### Logs

```bash
tail -f server.log
```

### Foreground (debugging)

```bash
source venv/bin/activate
python fastapi_server.py

# or, injecting secrets from 1Password:
op run --env-file .env -- python fastapi_server.py
```

### Rotating a credential

Update the value in your secret store, then restart the server:
```bash
./restart_all.sh
```

---

## API Endpoints

### Public

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Homepage with login link |
| `GET` | `/health` | Health check |

### External (internal or external key)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/helm-get-sbom` | Get SBOM by device group ID or product UUID |
| `POST` | `/api/list-helm-sbom-device-groups` | List Viper device groups matched to Helm SBOMs |

### Internal only

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/helm-upload-sbom` | Upload SBOM to Helm |
| `POST` | `/api/helm-export-sbom` | Export SBOM from Helm |
| `POST` | `/api/helm-create-product` | Create product/version in Helm |
| `POST` | `/api/viper-device-groups` | List all Viper device groups |
| `POST` | `/api/helm-viper-sync` | Sync Helm SBOM → Viper |
| `POST` | `/api/viper-vuln-sync` | Bulk sync vulnerabilities to Viper |

### Auth (SSO)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/login` | Start Google OAuth flow |
| `GET` | `/auth/callback` | OAuth callback (handled automatically) |
| `POST` | `/auth/regenerate` | Regenerate personal API key |
| `POST` | `/auth/viper-key/regenerate` | Regenerate shared Viper app key |
| `GET` | `/auth/logout` | Log out |

Interactive docs: `https://helm-api.com/docs`

---

## Authentication

All protected endpoints require:

```
Authorization: Bearer YOUR_API_KEY
```

API keys (`api_keys.txt`, `external_api_keys.txt`) are read from disk on every request — SSO-generated keys work immediately without a restart. Rotating an environment secret requires a server restart.

---

## Troubleshooting

### Port already in use
```bash
lsof -ti:8000 | xargs kill -9
./start_server.sh
```

### Module not found
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Invalid API key
- Confirm key is in `api_keys.txt` (internal) or `external_api_keys.txt` (external)
- No leading/trailing spaces on the key line
- Header format: `Authorization: Bearer YOUR_KEY`

### OAuth "invalid_client" error
- Verify `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` reached the process
- Redirect URI must match exactly: `https://helm-api.com/auth/callback`

## License

Released under the [MIT License](LICENSE).
