#!/usr/bin/env python3
"""
FastAPI server with OpenAPI compliance, rate limiting, and authentication.
Provides automatic OpenAPI spec generation and interactive documentation.
"""

import time
import os
import logging
from datetime import datetime
from collections import defaultdict
from threading import Lock
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Security, Request, BackgroundTasks, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import uvicorn

from models import (
    GetSbomRequest, GetSbomResponse,
    UploadSbomRequest, UploadSbomResponse,
    ExportSbomRequest, ExportSbomResponse,
    CreateProductRequest, CreateProductResponse,
    ViperDeviceGroupsResponse, MatchedDeviceGroupsResponse,
    ViperSyncRequest, ViperSyncResponse,
    ViperVulnSyncRequest, ViperVulnSyncResponse,
    RequestVulnSyncRequest,
    ExternalVulnSyncRequest, ExternalVulnSyncAcceptedResponse,
    TestResponse, HealthResponse, ServerStatusResponse,
    ErrorResponse, EmptyRequest
)

from config import (
    API_KEYS_FILE,
    EXTERNAL_API_KEYS_FILE,
    BLOCKED_IPS_FILE,
    RATE_LIMIT_WINDOW,
    RATE_LIMIT_MAX_REQUESTS,
    GLOBAL_RATE_LIMIT_WINDOW,
    GLOBAL_RATE_LIMIT_MAX_REQUESTS,
    DEFAULT_HOST,
    DEFAULT_PORT,
    SESSION_SECRET_KEY,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
)

# Initialize FastAPI app
app = FastAPI(
    title="Helm SBOM API",
    description="""
API for managing Software Bill of Materials (SBOM) data with Helm vulnerability management platform.

## Authentication

All protected endpoints require Bearer token authentication using API keys.

### Key Types
- **Internal Keys**: Full access to all endpoints
- **External Keys**: Read-only access to SBOM retrieval only

Include your API key in the Authorization header:
```
Authorization: Bearer YOUR_API_KEY
```

## Rate Limiting
- **Global**: 60 requests per minute
- **Per IP**: 10 requests per minute

## Access Levels
- **Public**: No authentication required (/, /health)
- **External**: External or internal keys (/api/helm-get-sbom, /api/list-helm-sbom-device-groups, /api/request-vuln-sync, /api/external-vuln-sync)
- **Internal**: Internal keys only (all other /api/* endpoints)
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add session middleware for OAuth
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET_KEY)

# Security scheme
security = HTTPBearer()

# Rate limiting storage
rate_limit_data = defaultdict(list)
global_rate_limit_data = []
rate_limit_lock = Lock()
global_rate_limit_lock = Lock()

# Server start time
SERVER_START_TIME = time.time()


def load_api_keys():
    """Load internal API keys from file (full access)."""
    keys = set()
    if os.path.exists(API_KEYS_FILE):
        with open(API_KEYS_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '#' in line:
                    key = line.split('#')[0].strip()
                else:
                    key = line
                if key:
                    keys.add(key)
    return keys


def load_external_api_keys():
    """Load external API keys from file (limited to SBOM operations)."""
    keys = set()
    if os.path.exists(EXTERNAL_API_KEYS_FILE):
        with open(EXTERNAL_API_KEYS_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '#' in line:
                    key = line.split('#')[0].strip()
                else:
                    key = line
                if key:
                    keys.add(key)
    return keys


def load_blocked_ips():
    """Load blocked IPs from file."""
    blocked = set()
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith('#'):
                    blocked.add(ip)
    return blocked


# Load API keys and blocked IPs at startup (refreshed on each request)
INTERNAL_API_KEYS = load_api_keys()
EXTERNAL_API_KEYS = load_external_api_keys()
BLOCKED_IPS = load_blocked_ips()


def get_all_valid_keys() -> tuple[set, set]:
    """Reload keys from disk on every call to pick up SSO-generated keys."""
    internal = load_api_keys()
    external = load_external_api_keys()

    # Also accept the Viper app key as an external key
    from auth_sso import get_viper_app_key
    viper_key = get_viper_app_key()
    if viper_key:
        external.add(viper_key)

    return internal, external

# Define external-accessible endpoints
EXTERNAL_ENDPOINTS = {'/api/helm-get-sbom', '/api/list-helm-sbom-device-groups', '/api/request-vuln-sync', '/api/external-vuln-sync'}


def check_rate_limit(client_ip: str) -> bool:
    """Check if request is within rate limits."""
    current_time = time.time()

    # Check global rate limit
    with global_rate_limit_lock:
        # Remove old entries
        global_rate_limit_data[:] = [
            t for t in global_rate_limit_data
            if current_time - t < GLOBAL_RATE_LIMIT_WINDOW
        ]

        if len(global_rate_limit_data) >= GLOBAL_RATE_LIMIT_MAX_REQUESTS:
            return False

        global_rate_limit_data.append(current_time)

    # Check per-IP rate limit
    with rate_limit_lock:
        # Remove old entries for this IP
        rate_limit_data[client_ip] = [
            t for t in rate_limit_data[client_ip]
            if current_time - t < RATE_LIMIT_WINDOW
        ]

        if len(rate_limit_data[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
            return False

        rate_limit_data[client_ip].append(current_time)

    return True


auth_logger = logging.getLogger("auth")


def verify_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> tuple[str, str]:
    """
    Verify API key and return (key_type, api_key).
    Raises HTTPException if invalid.
    """
    api_key = credentials.credentials
    internal_keys, external_keys = get_all_valid_keys()

    # Check internal keys first (full access)
    if api_key in internal_keys:
        return ('internal', api_key)

    # Check external keys (limited access)
    if api_key in external_keys:
        return ('external', api_key)

    # Invalid key
    truncated = api_key
    auth_logger.warning(
        "AUTH REJECTED: ip=%s path=%s reason=invalid_key token=%s",
        request.client.host if request.client else "unknown", request.url.path, truncated
    )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key"
    )


def verify_internal_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> str:
    """
    Verify API key is internal (full access).
    Raises HTTPException if not internal or invalid.
    """
    api_key = credentials.credentials
    internal_keys, external_keys = get_all_valid_keys()

    if api_key not in internal_keys:
        truncated = api_key
        if api_key in external_keys:
            auth_logger.warning(
                "AUTH REJECTED: ip=%s path=%s reason=external_key_on_internal_endpoint token=%s",
                request.client.host if request.client else "unknown", request.url.path, truncated
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: External keys cannot access this endpoint"
            )
        else:
            auth_logger.warning(
                "AUTH REJECTED: ip=%s path=%s reason=invalid_key token=%s",
                request.client.host if request.client else "unknown", request.url.path, truncated
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key"
            )

    return api_key


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Rate limiting and IP blocking middleware."""
    client_ip = request.client.host if request.client else "unknown"

    # Check if IP is blocked
    if client_ip in BLOCKED_IPS:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "IP address blocked"}
        )

    # Check rate limits (skip for public endpoints)
    if not request.url.path in ['/', '/health', '/docs', '/redoc', '/openapi.json']:
        if not check_rate_limit(client_ip):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"error": "Rate limit exceeded"}
            )

    response = await call_next(request)
    return response


# Public Endpoints

@app.get(
    "/",
    response_class=HTMLResponse,
    tags=["Public"],
    summary="Server status",
    description="Get basic server status and links. No authentication required."
)
async def root():
    """Get server status."""
    oauth_enabled = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)

    oauth_section = """
        <div class="card">
            <h2>🔑 Get API Key</h2>
            <p>Generate your API key using Google Single Sign-On:</p>
            <a href="/auth/login" class="button">Login with Google</a>
        </div>
    """ if oauth_enabled else """
        <div class="card">
            <h2>🔑 Get API Key</h2>
            <p>Contact your administrator for API access.</p>
        </div>
    """

    return HTMLResponse(f"""
    <html>
        <head>
            <title>Helm API</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    max-width: 900px;
                    margin: 50px auto;
                    padding: 20px;
                    background: #f5f5f5;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 40px;
                    border-radius: 8px;
                    text-align: center;
                    margin-bottom: 30px;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 36px;
                }}
                .header p {{
                    margin: 10px 0 0 0;
                    opacity: 0.9;
                }}
                .card {{
                    background: white;
                    padding: 25px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    margin-bottom: 20px;
                }}
                .card h2 {{
                    margin-top: 0;
                    color: #333;
                }}
                .button {{
                    display: inline-block;
                    background: #007bff;
                    color: white;
                    padding: 12px 24px;
                    text-decoration: none;
                    border-radius: 4px;
                    margin: 10px 10px 10px 0;
                    transition: background 0.3s;
                }}
                .button:hover {{
                    background: #0056b3;
                }}
                .button-secondary {{
                    background: #6c757d;
                }}
                .button-secondary:hover {{
                    background: #545b62;
                }}
                .status {{
                    display: inline-block;
                    background: #28a745;
                    color: white;
                    padding: 5px 15px;
                    border-radius: 20px;
                    font-size: 14px;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Helm API</h1>
                <p>Software Bill of Materials & Vulnerability Management</p>
                <span class="status">● Online</span>
            </div>

            {oauth_section}

            <div class="card">
                <h2>📚 Documentation</h2>
                <p>Explore the interactive API documentation:</p>
                <a href="/docs" class="button">API Documentation</a>
            </div>

            <div class="card">
                <h2>🔌 API Endpoints</h2>
                <p><strong>Base URL:</strong> <code>https://helm-api.com</code></p>
                <br>
                <p><strong>External Access (Read-Only):</strong></p>
                <ul>
                    <li><code>POST /api/helm-get-sbom</code> - Retrieve SBOM</li>
                    <li><code>POST /api/list-helm-sbom-device-groups</code> - List device groups with Helm SBOMs</li>
                    <li><code>POST /api/request-vuln-sync</code> - Request vulnerability sync by device group ID</li>
                    <li><code>POST /api/external-vuln-sync</code> - Async webhook-based vulnerability sync across all device groups</li>
                </ul>
                <p><strong>Internal Access (Full Control):</strong></p>
                <ul>
                    <li><code>POST /api/helm-upload-sbom</code> - Upload SBOM</li>
                    <li><code>POST /api/helm-viper-sync</code> - Sync with Viper</li>
                    <li><code>POST /api/viper-vuln-sync</code> - Sync vulnerabilities</li>
                    <li>And more...</li>
                </ul>
            </div>

            <div class="card">
                <h2>ℹ️ About</h2>
                <p>This API provides integration between Helm vulnerability management and Viper device management platforms.</p>
                <p><strong>Support:</strong> Contact your administrator</p>
            </div>
        </body>
    </html>
    """)


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Public"],
    summary="Health check",
    description="Get detailed server health and configuration. No authentication required."
)
async def health():
    """Health check endpoint."""
    uptime = time.time() - SERVER_START_TIME

    return {
        "status": "healthy",
        "uptime_seconds": uptime,
        "internal_keys": len(INTERNAL_API_KEYS),
        "external_keys": len(EXTERNAL_API_KEYS),
        "rate_limit_global": GLOBAL_RATE_LIMIT_MAX_REQUESTS,
        "rate_limit_per_ip": RATE_LIMIT_MAX_REQUESTS
    }


# OAuth/SSO Authentication Endpoints

@app.get(
    "/auth/login",
    response_class=HTMLResponse,
    tags=["Authentication"],
    summary="SSO Login",
    description="Initiate Google OAuth login for self-serve API key generation"
)
async def auth_login(request: Request):
    """Redirect to Google OAuth login."""
    # Check if OAuth is configured
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return HTMLResponse("""
        <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px;">
                <h1 style="color: #dc3545;">❌ OAuth Not Configured</h1>
                <p>Self-serve API key generation is not available.</p>
                <p>Please contact your administrator to configure Google OAuth credentials.</p>
            </body>
        </html>
        """)

    from auth_sso import oauth
    redirect_uri = request.url_for('auth_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri, prompt='select_account')


@app.get(
    "/auth/callback",
    response_class=HTMLResponse,
    tags=["Authentication"],
    summary="OAuth Callback",
    description="Handle OAuth callback and generate API key"
)
async def auth_callback(request: Request, regenerate: Optional[str] = None):
    """Handle OAuth callback."""
    try:
        from auth_sso import oauth, get_or_create_api_key

        # Get token from OAuth provider
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get('userinfo')

        if not user_info:
            raise HTTPException(status_code=400, detail="Failed to get user info")

        email = user_info.get('email')
        if not email:
            raise HTTPException(status_code=400, detail="Email not provided by OAuth")

        # Store email in session for regenerate
        request.session['user_email'] = email

        # Check if regenerating
        force_regenerate = regenerate == 'true'

        # Get or create API key
        result = get_or_create_api_key(email, force_regenerate=force_regenerate)

        if not result['success']:
            return HTMLResponse(f"""
            <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px;">
                    <h1 style="color: #dc3545;">❌ Access Denied</h1>
                    <p>Your email address (<strong>{email}</strong>) is not whitelisted for API access.</p>
                    <p>Please contact your administrator to request access.</p>
                    <br>
                    <a href="/" style="color: #007bff;">Return to Home</a>
                </body>
            </html>
            """)

        # Success - show API keys
        key_type = "Internal (Full Access)" if result['is_internal'] else "External (Read-Only)"

        if force_regenerate:
            is_new_text = "regenerated"
            action_text = "Your developer API key has been regenerated. The old key is now invalid."
        elif result['is_new']:
            is_new_text = "generated"
            action_text = "A new developer API key has been generated for your account."
        else:
            is_new_text = "retrieved"
            action_text = "Your existing developer API key is shown below."

        # Get Viper app key
        from auth_sso import ensure_viper_app_key_exists
        viper_key = ensure_viper_app_key_exists()

        return HTMLResponse(f"""
        <html>
            <head>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        max-width: 700px;
                        margin: 50px auto;
                        padding: 20px;
                        background: #f5f5f5;
                    }}
                    .container {{
                        background: white;
                        padding: 30px;
                        border-radius: 8px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    }}
                    .success {{
                        color: #28a745;
                        font-size: 24px;
                        margin-bottom: 20px;
                    }}
                    .key-box {{
                        background: #f8f9fa;
                        border: 2px solid #007bff;
                        border-radius: 4px;
                        padding: 15px;
                        margin: 20px 0;
                        word-break: break-all;
                        font-family: monospace;
                        font-size: 14px;
                    }}
                    .warning {{
                        background: #fff3cd;
                        border: 1px solid #ffc107;
                        border-radius: 4px;
                        padding: 15px;
                        margin: 20px 0;
                    }}
                    .info {{
                        background: #d1ecf1;
                        border: 1px solid #17a2b8;
                        border-radius: 4px;
                        padding: 15px;
                        margin: 20px 0;
                    }}
                    code {{
                        background: #e9ecef;
                        padding: 2px 6px;
                        border-radius: 3px;
                        font-family: monospace;
                    }}
                    .copy-btn {{
                        background: #007bff;
                        color: white;
                        border: none;
                        padding: 10px 20px;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 14px;
                    }}
                    .copy-btn:hover {{
                        background: #0056b3;
                    }}
                    .regenerate-btn {{
                        background: #dc3545;
                        color: white;
                        border: none;
                        padding: 10px 20px;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 14px;
                        margin-left: 10px;
                    }}
                    .regenerate-btn:hover {{
                        background: #c82333;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1 class="success">✅ API Keys {is_new_text.capitalize()}!</h1>
                    <p><strong>Email:</strong> {email}</p>
                    <p><strong>Access Level:</strong> {key_type}</p>
                    <p>{action_text}</p>

                    <h3 style="margin-top: 30px;">🔑 Your Developer Key</h3>
                    <p>Use this key for manual testing with curl, Postman, etc.</p>
                    <div class="key-box" id="devKey">{result['api_key']}</div>
                    <button class="copy-btn" onclick="copyKey('devKey')">📋 Copy Developer Key</button>
                    <button class="regenerate-btn" onclick="regenerateKey()">🔄 Regenerate My Key</button>

                    <h3 style="margin-top: 30px;">🐍 Viper Application Key</h3>
                    <div class="key-box" id="viperKey">{viper_key}</div>
                    <button class="copy-btn" onclick="copyKey('viperKey')">📋 Copy Viper Key</button>
                    <p style="color: #666; font-size: 13px; margin-top: 8px;">To regenerate this key, contact your administrator.</p>

                    <div class="warning">
                        <strong>⚠️ Developer Key:</strong> Personal key for manual testing. Regenerating only affects your own key.
                    </div>

                    <div class="info">
                        <h3>Usage:</h3>
                        <p>Include this key in your API requests:</p>
                        <code>Authorization: Bearer {result['api_key'][:20]}...</code>
                        <br><br>
                        <p><strong>API Documentation:</strong> <a href="/docs" target="_blank">https://helm-api.com/docs</a></p>
                        <p><strong>Base URL:</strong> <code>https://helm-api.com</code></p>
                    </div>

                    <p><a href="/" style="color: #007bff;">Return to Home</a></p>
                </div>

                <script>
                    function copyKey(keyId) {{
                        const keyText = document.getElementById(keyId).textContent;
                        navigator.clipboard.writeText(keyText).then(function() {{
                            const keyName = keyId === 'devKey' ? 'Developer key' : 'Viper app key';
                            alert(keyName + ' copied to clipboard!');
                        }}, function() {{
                            alert('Failed to copy. Please copy manually.');
                        }});
                    }}

                    function regenerateKey() {{
                        if (confirm('Are you sure you want to regenerate YOUR DEVELOPER KEY? This will only affect your personal key, not the Viper app key.')) {{
                            window.location.href = '/auth/regenerate';
                        }}
                    }}

                </script>
            </body>
        </html>
        """)

    except Exception as e:
        return HTMLResponse(f"""
        <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px;">
                <h1 style="color: #dc3545;">❌ Authentication Error</h1>
                <p>An error occurred during authentication:</p>
                <p style="color: #666;"><em>{str(e)}</em></p>
                <br>
                <a href="/auth/login" style="color: #007bff;">Try Again</a>
            </body>
        </html>
        """)


@app.get(
    "/auth/regenerate",
    response_class=RedirectResponse,
    tags=["Authentication"],
    summary="Regenerate API Key",
    description="Regenerate API key (requires active session)"
)
async def auth_regenerate(request: Request):
    """Regenerate API key by redirecting to OAuth with regenerate flag."""
    # Check if user has session
    if 'user_email' not in request.session:
        # Need to re-authenticate
        from auth_sso import oauth
        redirect_uri = request.url_for('auth_callback').include_query_params(regenerate='true')
        return await oauth.google.authorize_redirect(request, redirect_uri)

    # User has session, redirect to callback with regenerate flag
    from auth_sso import oauth
    redirect_uri = request.url_for('auth_callback').include_query_params(regenerate='true')
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get(
    "/auth/viper-key/regenerate",
    response_class=RedirectResponse,
    tags=["Authentication"],
    summary="Regenerate Viper App Key",
    description="Regenerate the shared Viper application API key"
)
async def regenerate_viper_key(request: Request):
    """Regenerate Viper app key."""
    # Check if user is authenticated
    email = request.session.get('user_email')
    if not email:
        # Redirect to login
        return RedirectResponse(url='/auth/login')

    from auth_sso import regenerate_viper_app_key, is_email_whitelisted

    # Check if user is whitelisted (Tim or Cassidy)
    if not is_email_whitelisted(email):
        return HTMLResponse("""
        <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px;">
                <h1 style="color: #dc3545;">❌ Unauthorized</h1>
                <p>Only authorized users can regenerate the Viper app key.</p>
                <br>
                <a href="/" style="color: #007bff;">Return to Home</a>
            </body>
        </html>
        """)

    # Regenerate the key
    new_key = regenerate_viper_app_key(email)

    return HTMLResponse(f"""
    <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    max-width: 700px;
                    margin: 50px auto;
                    padding: 20px;
                    background: #f5f5f5;
                }}
                .container {{
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .success {{
                    color: #28a745;
                    font-size: 24px;
                }}
                .key-box {{
                    background: #f8f9fa;
                    border: 2px solid #dc3545;
                    border-radius: 4px;
                    padding: 15px;
                    margin: 20px 0;
                    word-break: break-all;
                    font-family: monospace;
                    font-size: 14px;
                }}
                .warning {{
                    background: #fff3cd;
                    border: 1px solid #ffc107;
                    border-radius: 4px;
                    padding: 15px;
                    margin: 20px 0;
                }}
                .copy-btn {{
                    background: #007bff;
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 4px;
                    cursor: pointer;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1 class="success">✅ Viper App Key Regenerated!</h1>
                <p><strong>Regenerated by:</strong> {email}</p>
                <p>The old Viper app key has been invalidated. Update your Viper application with the new key below.</p>

                <h3>🐍 New Viper Application Key</h3>
                <div class="key-box" id="viperKey">{new_key}</div>
                <button class="copy-btn" onclick="copyKey()">📋 Copy Viper Key</button>

                <div class="warning">
                    <strong>⚠️ IMPORTANT:</strong> Update the Viper application configuration immediately!
                    <br><br>
                    The old key is now invalid and the Viper app will not work until you update it.
                </div>

                <p style="margin-top: 30px;">
                    <a href="/auth/login" style="color: #007bff;">View All Keys</a> |
                    <a href="/" style="color: #007bff;">Return to Home</a>
                </p>
            </div>

            <script>
                function copyKey() {{
                    const keyText = document.getElementById('viperKey').textContent;
                    navigator.clipboard.writeText(keyText).then(function() {{
                        alert('Viper app key copied to clipboard!');
                    }}, function() {{
                        alert('Failed to copy. Please copy manually.');
                    }});
                }}
            </script>
        </body>
    </html>
    """)


@app.get(
    "/auth/logout",
    response_class=HTMLResponse,
    tags=["Authentication"],
    summary="Logout",
    description="Clear session and logout"
)
async def auth_logout(request: Request):
    """Logout and clear session."""
    request.session.clear()
    return HTMLResponse("""
    <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px;">
            <h1>👋 Logged Out</h1>
            <p>You have been successfully logged out.</p>
            <br>
            <a href="/auth/login" style="color: #007bff;">Login Again</a> |
            <a href="/" style="color: #007bff;">Return to Home</a>
        </body>
    </html>
    """)


# External Endpoints (accessible to external and internal keys)

@app.post(
    "/api/helm-get-sbom",
    response_model=GetSbomResponse,
    responses={
        200: {"description": "SBOM retrieved successfully"},
        400: {"model": ErrorResponse, "description": "Bad request - missing identifier"},
        401: {"model": ErrorResponse, "description": "Invalid API key"},
        404: {"description": "SBOM not found or not unique"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
        500: {"model": ErrorResponse, "description": "Internal server error"}
    },
    tags=["External Access"],
    summary="Retrieve SBOM by identifier",
    description="""
    Retrieves a Software Bill of Materials (SBOM) from Helm using either a Viper device group ID
    or a Helm product version UUID. Uses workspace configured in config.py.

    **Access Level**: External (Read-Only) + Internal (Full Access)

    At least one identifier must be provided. If both are provided, product_version_uuid takes precedence.
    """
)
async def get_helm_sbom(
    request: GetSbomRequest,
    auth: tuple = Security(verify_api_key)
):
    """Get SBOM by device group ID or product version UUID."""
    # Validate at least one identifier
    if not request.device_group_id and not request.product_version_uuid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either device_group_id or product_version_uuid is required"
        )

    try:
        import sys
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from helm_get_sbom import get_sbom

        result = get_sbom(
            device_group_id=request.device_group_id,
            product_version_uuid=request.product_version_uuid,
            workspace_name=None  # Always use config default
        )

        if result is None or not result.get('success'):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

        return result

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get SBOM: {str(e)}"
        )


@app.post(
    "/api/list-helm-sbom-device-groups",
    response_model=MatchedDeviceGroupsResponse,
    responses={
        200: {"description": "Matched device groups retrieved successfully"},
        401: {"model": ErrorResponse, "description": "Invalid API key"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
        500: {"model": ErrorResponse, "description": "Internal server error"}
    },
    tags=["External Access"],
    summary="Get device groups with Helm product versions",
    description="""
    Get device groups from Viper that have matching product versions in Helm.

    **Access Level**: External (Read-Only) + Internal (Full Access)

    Returns device groups where the device group ID matches a Helm product version name,
    including the Helm product name and SBOM ID (helmSbomId).
    """
)
async def get_matched_device_groups(
    request: EmptyRequest,
    auth: tuple = Security(verify_api_key)
):
    """Get device groups that have product versions in Helm."""
    try:
        import sys
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from helm_viper_device_groups import get_matched_device_groups

        # Load Viper API key
        viper_api_key = os.environ.get('VIPER_API_KEY')

        if not viper_api_key:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Viper API key not configured"
            )

        # Get matched device groups
        matched_groups = get_matched_device_groups(viper_api_key)

        return {
            'success': True,
            'device_groups': matched_groups,
            'count': len(matched_groups)
        }

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        print(f"Error getting matched device groups: {e}")
        print(traceback.format_exc())
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get matched device groups: {str(e)}"
        )


# Internal Endpoints (accessible to internal keys only)

@app.post(
    "/api/helm-upload-sbom",
    response_model=UploadSbomResponse,
    responses={
        200: {"description": "SBOM uploaded successfully"},
        400: {"model": ErrorResponse, "description": "Bad request"},
        401: {"model": ErrorResponse, "description": "Invalid API key"},
        403: {"model": ErrorResponse, "description": "Insufficient permissions"},
        500: {"model": ErrorResponse, "description": "Internal server error"}
    },
    tags=["Internal"],
    summary="Upload SBOM to Helm",
    description="""
    Upload a Software Bill of Materials (SBOM) to Helm product version.

    **Access Level**: Internal Only

    Requires base64-encoded SBOM content. Supports CycloneDX and SPDX formats.
    """
)
async def upload_helm_sbom(
    request: UploadSbomRequest,
    api_key: str = Security(verify_internal_key)
):
    """Upload SBOM to Helm product version."""
    # Validate at least one identifier
    if not request.device_group_id and not request.product_version_uuid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either device_group_id or product_version_uuid is required"
        )

    try:
        import sys
        import base64
        import tempfile
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from helm_upload_sbom import upload_sbom

        # Decode SBOM content
        try:
            sbom_data = base64.b64decode(request.sbom_content)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid base64-encoded SBOM content: {str(e)}"
            )

        # Write to temp file
        temp_file = tempfile.NamedTemporaryFile(
            mode='wb',
            suffix='.json',
            delete=False
        )
        temp_file.write(sbom_data)
        temp_file.close()

        try:
            result = upload_sbom(
                device_group_id=request.device_group_id,
                product_version_uuid=request.product_version_uuid,
                workspace_name=request.workspace_name,
                sbom_file_path=temp_file.name,
                file_type=request.file_type.value
            )

            if not result or not result.get('success'):
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to upload SBOM"
                )

            return result

        finally:
            # Clean up temp file
            try:
                os.unlink(temp_file.name)
            except:
                pass

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload SBOM: {str(e)}"
        )


@app.post(
    "/api/helm-export-sbom",
    response_model=ExportSbomResponse,
    tags=["Internal"],
    summary="Export SBOM from Helm",
    description="Export SBOM in CycloneDX format. Internal keys only."
)
async def export_helm_sbom(
    request: ExportSbomRequest,
    api_key: str = Security(verify_internal_key)
):
    """Export SBOM from Helm."""
    try:
        import sys
        import json
        import tempfile
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from helm_export_sbom import export_sbom

        # Export to temp file
        temp_path = os.path.join(
            tempfile.gettempdir(),
            f"sbom_{request.product_name}_{request.version}.json"
        )

        result_path = export_sbom(
            request.product_name,
            request.version,
            request.workspace_name,
            temp_path
        )

        if not result_path or not os.path.exists(result_path):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Failed to export SBOM"
            )

        # Read SBOM content
        with open(result_path, 'r') as f:
            sbom_content = json.load(f)

        return {
            "success": True,
            "sbom": sbom_content,
            "product_name": request.product_name,
            "version": request.version,
            "file_path": result_path
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to export SBOM: {str(e)}"
        )


@app.post(
    "/api/helm-create-product",
    response_model=CreateProductResponse,
    tags=["Internal"],
    summary="Create Helm product and version",
    description="Create new product and version in Helm. Internal keys only."
)
async def create_helm_product(
    request: CreateProductRequest,
    api_key: str = Security(verify_internal_key)
):
    """Create Helm product and version."""
    try:
        import sys
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from helm_create_product import create_helm_product_and_version

        result = create_helm_product_and_version(
            request.product_name,
            request.version,
            request.workspace_name
        )

        if not result or not result.get('success'):
            detail = result.get('error') if result else None
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=detail or "Failed to create product"
            )

        # Build a human-readable message for the response model
        prod_state = "created" if result.get('product_created') else "already existed"
        vers_state = "created" if result.get('version_created') else "already existed"
        result['message'] = (
            f"Product '{result.get('product_name')}' {prod_state}; "
            f"version '{result.get('version')}' {vers_state}"
        )

        return result

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create product: {str(e)}"
        )


@app.post(
    "/api/viper-device-groups",
    response_model=ViperDeviceGroupsResponse,
    tags=["Internal"],
    summary="List Viper device groups",
    description="List all device groups from Viper. Internal keys only."
)
async def list_viper_device_groups(
    request: EmptyRequest,
    api_key: str = Security(verify_internal_key)
):
    """List all Viper device groups."""
    try:
        import sys
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from helm_viper_integration import list_viper_device_groups as list_dg

        # Load Viper API key
        viper_api_key = os.environ.get('VIPER_API_KEY')

        if not viper_api_key:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Viper API key not configured"
            )

        result = list_dg(viper_api_key)

        if not result or not result.get('success'):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to list device groups"
            )

        return result

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list device groups: {str(e)}"
        )


@app.post(
    "/api/helm-viper-sync",
    response_model=ViperSyncResponse,
    tags=["Internal"],
    summary="Sync SBOM between Helm and Viper",
    description="""
    Synchronize SBOM between Helm and Viper by creating product/version in Helm,
    uploading SBOM, and updating Viper device group with Helm UUID. Internal keys only.
    """
)
async def sync_helm_viper(
    request: ViperSyncRequest,
    api_key: str = Security(verify_internal_key)
):
    """Sync SBOM between Helm and Viper."""
    try:
        import sys
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from helm_viper_integration import sync_device_group_to_helm

        result = sync_device_group_to_helm(
            request.device_group_id,
            request.product_name,
            request.version,
            request.workspace_name
        )

        if not result or not result.get('success'):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to sync with Viper"
            )

        return result

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to sync with Viper: {str(e)}"
        )


@app.post(
    "/api/viper-vuln-sync",
    response_model=ViperVulnSyncResponse,
    tags=["Internal"],
    summary="Bulk sync vulnerabilities from Helm to Viper",
    description="""
Fetch vulnerabilities from Helm for a product version and bulk sync them to Viper.

**Access Level:** Internal only (requires internal API key)

**Process:**
1. Fetch vulnerabilities from Helm for given product version UUID
2. Transform each vulnerability from Helm format to Viper format
3. Generate required fields (CPE, SARIF) from Helm data
4. Bulk create vulnerabilities in Viper
5. Return sync results

**Field Transformations:**
- Generates CPE 2.3 format from product/vendor/version data
- Creates SARIF format from vulnerability details
- Maps CVSS scores to severity levels (Critical/High/Medium/Low)
- Extracts exploit indicators and reference links

**Note:** This operation may take some time for large numbers of vulnerabilities.
    """
)
async def viper_vuln_sync(
    request: ViperVulnSyncRequest,
    api_key: str = Security(verify_internal_key)
) -> ViperVulnSyncResponse:
    """Bulk sync vulnerabilities from Helm to Viper."""
    try:
        # Import here to avoid circular imports
        from helm_get_sbom import get_vulnerabilities_for_product_version
        from helm_viper_vuln_sync import transform_helm_vuln_to_viper, sync_vulnerabilities_to_viper
        import os

        # Load Helm credentials
        helm_client_id = os.environ.get('HELM_CLIENT_ID')
        helm_client_secret = os.environ.get('HELM_CLIENT_SECRET')

        if not helm_client_id or not helm_client_secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Helm API credentials not configured"
            )

        # Load Viper API key
        viper_api_key = os.environ.get('VIPER_API_KEY')

        if not viper_api_key:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Viper API key not configured"
            )

        # Step 1: Fetch vulnerabilities from Helm
        helm_vulns_result = get_vulnerabilities_for_product_version(
            product_version_uuid=request.product_version_uuid,
            client_id=helm_client_id,
            client_secret=helm_client_secret
        )

        if not helm_vulns_result.get('success'):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to fetch vulnerabilities from Helm: {helm_vulns_result.get('error')}"
            )

        helm_vulns = helm_vulns_result.get('vulnerabilities', [])

        if not helm_vulns:
            return ViperVulnSyncResponse(
                success=True,
                synced_count=0,
                failed_count=0,
                viper_vulnerabilities=[],
                errors=["No vulnerabilities found in Helm for this product version"]
            )

        # Step 2: Filter vulnerabilities based on options
        min_severity_map = {"Low": 0.0, "Medium": 4.0, "High": 7.0, "Critical": 9.0}
        min_score = min_severity_map.get(request.sync_options.min_severity, 0.0)

        filtered_vulns = []
        for vuln in helm_vulns:
            # Check severity
            severities = vuln.get("vulnerability_severity", [])
            score = severities[0].get("score", 0.0) if severities else 0.0

            if score < min_score:
                continue

            # Check if resolved (if we shouldn't include them)
            if not request.sync_options.include_resolved:
                patch_state = vuln.get("patch_state", "")
                if patch_state == "PATCHED":
                    continue

            filtered_vulns.append(vuln)

        if not filtered_vulns:
            return ViperVulnSyncResponse(
                success=True,
                synced_count=0,
                failed_count=0,
                viper_vulnerabilities=[],
                errors=[f"No vulnerabilities match criteria (min severity: {request.sync_options.min_severity})"]
            )

        # Step 2.5: Get device group CPE if device_group_id is provided
        device_group_cpe = None
        if request.device_group_id:
            try:
                import requests
                from ssl_helper import get_ca_bundle

                viper_url = f"https://viper-xi.vercel.app/api/v1/devicegroups/{request.device_group_id}"
                viper_headers = {
                    'Authorization': f'Bearer {viper_api_key}',
                    'Content-Type': 'application/json'
                }
                dg_response = requests.get(viper_url, headers=viper_headers, verify=get_ca_bundle())
                if dg_response.status_code == 200:
                    dg_data = dg_response.json()
                    device_group_cpe = dg_data.get('cpe')
            except Exception as e:
                # Non-fatal - will generate CPE from vulnerability data
                pass

        # Step 3: Transform vulnerabilities to Viper format
        viper_vulns = []
        transform_errors = []

        for helm_vuln in filtered_vulns:
            try:
                viper_vuln = transform_helm_vuln_to_viper(helm_vuln, request.device_group_id, device_group_cpe)
                viper_vulns.append(viper_vuln)
            except Exception as e:
                cve_id = helm_vuln.get("vulnerability_key", "UNKNOWN")
                transform_errors.append(f"Failed to transform {cve_id}: {str(e)}")

        if not viper_vulns:
            return ViperVulnSyncResponse(
                success=False,
                synced_count=0,
                failed_count=len(filtered_vulns),
                viper_vulnerabilities=[],
                errors=transform_errors
            )

        # Step 4: Bulk sync to Viper
        sync_result = sync_vulnerabilities_to_viper(viper_vulns, viper_api_key)

        # Add transform errors to sync errors
        all_errors = transform_errors + sync_result.get('errors', [])

        return ViperVulnSyncResponse(
            success=sync_result['success'],
            synced_count=sync_result['synced_count'],
            failed_count=sync_result['failed_count'] + len(transform_errors),
            viper_vulnerabilities=sync_result['viper_vulnerabilities'],
            errors=all_errors
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to sync vulnerabilities: {str(e)}"
        )


@app.post(
    "/api/request-vuln-sync",
    response_model=ViperVulnSyncResponse,
    tags=["External Access"],
    summary="Request vulnerability sync by device group ID",
    description="""
Request a vulnerability sync for a given device group ID. Resolves the device group to its
Helm product version, fetches vulnerabilities from Helm, and bulk syncs them to Viper.

**Access Level**: External (Read-Only) + Internal (Full Access)

**Process:**
1. Resolve device group ID to Helm product version UUID
2. Fetch vulnerabilities from Helm for that product version
3. Transform each vulnerability from Helm format to Viper format
4. Bulk create vulnerabilities in Viper
5. Return sync results

**Note:** This operation may take some time for large numbers of vulnerabilities.
    """
)
async def request_vuln_sync(
    request: RequestVulnSyncRequest,
    auth: tuple = Security(verify_api_key)
) -> ViperVulnSyncResponse:
    """Request vulnerability sync by device group ID."""
    try:
        from helm_get_sbom import find_product_version_by_device_group_id, get_vulnerabilities_for_product_version
        from helm_viper_vuln_sync import transform_helm_vuln_to_viper, sync_vulnerabilities_to_viper
        import os

        # Step 1: Resolve device group ID to product version UUID
        product_info = find_product_version_by_device_group_id(request.device_group_id)
        if not product_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No unique Helm product version found for device group ID: {request.device_group_id}"
            )

        product_version_uuid = product_info['product_version_uuid']

        # Step 2: Load credentials
        helm_client_id = os.environ.get('HELM_CLIENT_ID')
        helm_client_secret = os.environ.get('HELM_CLIENT_SECRET')

        if not helm_client_id or not helm_client_secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Helm API credentials not configured"
            )

        viper_api_key = os.environ.get('VIPER_API_KEY')

        if not viper_api_key:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Viper API key not configured"
            )

        # Step 3: Fetch vulnerabilities from Helm
        helm_vulns_result = get_vulnerabilities_for_product_version(
            product_version_uuid=product_version_uuid,
            client_id=helm_client_id,
            client_secret=helm_client_secret
        )

        if not helm_vulns_result.get('success'):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to fetch vulnerabilities from Helm: {helm_vulns_result.get('error')}"
            )

        helm_vulns = helm_vulns_result.get('vulnerabilities', [])

        if not helm_vulns:
            return ViperVulnSyncResponse(
                success=True,
                synced_count=0,
                failed_count=0,
                viper_vulnerabilities=[],
                errors=["No vulnerabilities found in Helm for this product version"]
            )

        # Step 4: Filter vulnerabilities based on options
        min_severity_map = {"Low": 0.0, "Medium": 4.0, "High": 7.0, "Critical": 9.0}
        min_score = min_severity_map.get(request.sync_options.min_severity, 0.0)

        filtered_vulns = []
        for vuln in helm_vulns:
            severities = vuln.get("vulnerability_severity", [])
            score = severities[0].get("score", 0.0) if severities else 0.0

            if score < min_score:
                continue

            if not request.sync_options.include_resolved:
                patch_state = vuln.get("patch_state", "")
                if patch_state == "PATCHED":
                    continue

            filtered_vulns.append(vuln)

        if not filtered_vulns:
            return ViperVulnSyncResponse(
                success=True,
                synced_count=0,
                failed_count=0,
                viper_vulnerabilities=[],
                errors=[f"No vulnerabilities match criteria (min severity: {request.sync_options.min_severity})"]
            )

        # Step 5: Get device group CPE
        device_group_cpe = None
        try:
            import requests as req
            from ssl_helper import get_ca_bundle

            viper_url = f"https://viper-xi.vercel.app/api/v1/devicegroups/{request.device_group_id}"
            viper_headers = {
                'Authorization': f'Bearer {viper_api_key}',
                'Content-Type': 'application/json'
            }
            dg_response = req.get(viper_url, headers=viper_headers, verify=get_ca_bundle())
            if dg_response.status_code == 200:
                dg_data = dg_response.json()
                device_group_cpe = dg_data.get('cpe')
        except Exception:
            # Non-fatal - will generate CPE from vulnerability data
            pass

        # Step 6: Transform vulnerabilities to Viper format
        viper_vulns = []
        transform_errors = []

        for helm_vuln in filtered_vulns:
            try:
                viper_vuln = transform_helm_vuln_to_viper(helm_vuln, request.device_group_id, device_group_cpe)
                viper_vulns.append(viper_vuln)
            except Exception as e:
                cve_id = helm_vuln.get("vulnerability_key", "UNKNOWN")
                transform_errors.append(f"Failed to transform {cve_id}: {str(e)}")

        if not viper_vulns:
            return ViperVulnSyncResponse(
                success=False,
                synced_count=0,
                failed_count=len(filtered_vulns),
                viper_vulnerabilities=[],
                errors=transform_errors
            )

        # Step 7: Bulk sync to Viper
        sync_result = sync_vulnerabilities_to_viper(viper_vulns, viper_api_key)

        all_errors = transform_errors + sync_result.get('errors', [])

        return ViperVulnSyncResponse(
            success=sync_result['success'],
            synced_count=sync_result['synced_count'],
            failed_count=sync_result['failed_count'] + len(transform_errors),
            viper_vulnerabilities=sync_result['viper_vulnerabilities'],
            errors=all_errors
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to sync vulnerabilities: {str(e)}"
        )


def _run_external_vuln_sync(
    matched_device_groups: list,
    helm_client_id: str,
    helm_client_secret: str,
    webhook_url: str,
    page_size: int,
    last_sync_epoch: float | None,
    not_after_epoch: float | None,
    viper_api_key: str = "",
):
    """
    Background task: fetch vulns for all matched device groups, filter by date,
    transform, paginate, and POST pages to webhook_url.
    """
    import math
    import requests as req
    from ssl_helper import get_ca_bundle
    from helm_get_sbom import get_vulnerabilities_for_product_version
    from helm_viper_vuln_sync import transform_helm_vuln_to_viper

    logger = logging.getLogger("external_vuln_sync")

    all_transformed = []

    for dg in matched_device_groups:
        product_version_uuid = dg["helmSbomId"]
        device_group_cpe = dg.get("cpe")
        device_group_id = dg["id"]

        try:
            result = get_vulnerabilities_for_product_version(
                product_version_uuid=product_version_uuid,
                client_id=helm_client_id,
                client_secret=helm_client_secret,
            )
        except Exception as exc:
            logger.error("Failed to fetch vulns for product version %s: %s", product_version_uuid, exc)
            continue

        if not result.get("success"):
            logger.warning("Helm returned failure for %s: %s", product_version_uuid, result.get("error"))
            continue

        for vuln in result.get("vulnerabilities", []):
            # Filter on vulnerability_association_date
            assoc_date_str = vuln.get("vulnerability_association_date")
            if assoc_date_str:
                try:
                    assoc_epoch = datetime.fromisoformat(assoc_date_str.replace("Z", "+00:00")).timestamp()
                except (ValueError, TypeError):
                    assoc_epoch = None
            else:
                assoc_epoch = None

            if last_sync_epoch is not None and assoc_epoch is not None:
                if assoc_epoch < last_sync_epoch:
                    continue
            if not_after_epoch is not None and assoc_epoch is not None:
                if assoc_epoch > not_after_epoch:
                    continue

            try:
                transformed = transform_helm_vuln_to_viper(vuln, device_group_id, device_group_cpe)
                all_transformed.append(transformed)
            except Exception as exc:
                cve_id = vuln.get("vulnerability_key", "UNKNOWN")
                logger.error("Transform failed for %s: %s", cve_id, exc)

    total_count = len(all_transformed)
    total_pages = max(1, math.ceil(total_count / page_size))

    logger.info("External vuln sync: %d vulns, %d pages -> %s", total_count, total_pages, webhook_url)

    for page_num in range(1, total_pages + 1):
        start = (page_num - 1) * page_size
        end = start + page_size
        page_items = all_transformed[start:end]

        payload = {
            "items": page_items,
            "page": page_num,
            "pageSize": page_size,
            "totalCount": total_count,
            "totalPages": total_pages,
            "next": None,
            "previous": None,
        }

        # Retry with exponential backoff
        for attempt in range(3):
            try:
                webhook_headers = {"Content-Type": "application/json"}
                if viper_api_key:
                    webhook_headers["Authorization"] = f"Bearer {viper_api_key}"
                resp = req.post(webhook_url, json=payload, headers=webhook_headers, timeout=30, verify=get_ca_bundle())
                if resp.status_code < 400:
                    logger.info("Webhook page %d/%d delivered (HTTP %d)", page_num, total_pages, resp.status_code)
                    break
                else:
                    logger.warning("Webhook page %d/%d got HTTP %d, attempt %d", page_num, total_pages, resp.status_code, attempt + 1)
            except Exception as exc:
                logger.warning("Webhook page %d/%d failed attempt %d: %s", page_num, total_pages, attempt + 1, exc)

            if attempt < 2:
                import time as _time
                _time.sleep(2 ** attempt)  # 1s, 2s
        else:
            logger.error("Webhook page %d/%d failed after 3 attempts", page_num, total_pages)


@app.post(
    "/api/external-vuln-sync",
    response_model=ExternalVulnSyncAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["External Access"],
    summary="Async webhook-based vulnerability sync across all matched device groups",
    description="""
Accepts a sync request and returns 202 immediately. In the background, fetches vulnerabilities
for ALL matched device groups from Helm, filters by vulnerability_association_date using the
provided last_sync / not_after bounds, transforms to Viper format, and POSTs paginated results
to the given webhook_url.

**Access Level**: External (Read-Only) + Internal (Full Access)

**Webhook payload format per page:**
```json
{
  "items": [...],
  "page": 1,
  "pageSize": 500,
  "totalCount": 1250,
  "totalPages": 3,
  "next": null,
  "previous": null
}
```
    """
)
async def external_vuln_sync(
    request: ExternalVulnSyncRequest,
    background_tasks: BackgroundTasks,
    auth: tuple = Security(verify_api_key),
):
    """Async webhook-based vulnerability sync across all matched device groups."""
    try:
        from helm_viper_device_groups import get_matched_device_groups as _get_matched_dgs

        # Load credentials
        helm_client_id = os.environ.get("HELM_CLIENT_ID")
        helm_client_secret = os.environ.get("HELM_CLIENT_SECRET")
        if not helm_client_id or not helm_client_secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Helm API credentials not configured",
            )

        viper_api_key = os.environ.get("VIPER_API_KEY")
        if not viper_api_key:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Viper API key not configured",
            )

        # Get all matched device groups
        matched = _get_matched_dgs(viper_api_key)

        if not matched:
            return ExternalVulnSyncAcceptedResponse(
                status="accepted",
                message="No matched device groups found — nothing to sync",
                matched_device_groups=0,
            )

        # Parse date bounds to epoch
        last_sync_epoch = None
        not_after_epoch = None
        if request.last_sync:
            try:
                last_sync_epoch = datetime.fromisoformat(request.last_sync.replace("Z", "+00:00")).timestamp()
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid last_sync timestamp: {request.last_sync}",
                )
        if request.not_after:
            try:
                not_after_epoch = datetime.fromisoformat(request.not_after.replace("Z", "+00:00")).timestamp()
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid not_after timestamp: {request.not_after}",
                )

        # Enqueue background work
        background_tasks.add_task(
            _run_external_vuln_sync,
            matched_device_groups=matched,
            helm_client_id=helm_client_id,
            helm_client_secret=helm_client_secret,
            webhook_url=request.webhook_url,
            page_size=request.pageSize,
            last_sync_epoch=last_sync_epoch,
            not_after_epoch=not_after_epoch,
            viper_api_key=viper_api_key,
        )

        return ExternalVulnSyncAcceptedResponse(
            status="accepted",
            message=f"Vulnerability sync started for {len(matched)} matched device groups. Results will be POSTed to {request.webhook_url}",
            matched_device_groups=len(matched),
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate external vuln sync: {str(e)}",
        )


if __name__ == "__main__":
    print("=" * 70)
    print("Starting Helm SBOM API Server (FastAPI)")
    print("=" * 70)
    print()
    print(f"Loaded {len(INTERNAL_API_KEYS)} internal API keys (full access)")
    print(f"Loaded {len(EXTERNAL_API_KEYS)} external API keys (read-only)")
    print(f"Blocked {len(BLOCKED_IPS)} IP addresses")
    print()
    print("Rate Limits:")
    print(f"  Global: {GLOBAL_RATE_LIMIT_MAX_REQUESTS} requests per {GLOBAL_RATE_LIMIT_WINDOW}s")
    print(f"  Per-IP: {RATE_LIMIT_MAX_REQUESTS} requests per {RATE_LIMIT_WINDOW}s")
    print()
    print("Endpoints:")
    print("  Public:")
    print("    GET  /               - Server status")
    print("    GET  /health         - Health check")
    print()
    print("  External (Read-Only):")
    print("    POST /api/helm-get-sbom          - Get SBOM")
    print("    POST /api/list-helm-sbom-device-groups  - Get device groups with Helm versions")
    print("    POST /api/request-vuln-sync      - Request vuln sync by device group ID")
    print("    POST /api/external-vuln-sync    - Async webhook vuln sync (all device groups)")
    print()
    print("  Internal (Full Access):")
    print("    POST /api/helm-upload-sbom       - Upload SBOM")
    print("    POST /api/helm-export-sbom       - Export SBOM")
    print("    POST /api/helm-create-product    - Create product/version")
    print("    POST /api/viper-device-groups    - List device groups")
    print("    POST /api/helm-viper-sync        - Sync Helm <-> Viper")
    print("    POST /api/viper-vuln-sync        - Bulk sync vulnerabilities to Viper")
    print()
    print("OpenAPI Documentation:")
    print(f"  Swagger UI: http://{DEFAULT_HOST}:{DEFAULT_PORT}/docs")
    print(f"  ReDoc:      http://{DEFAULT_HOST}:{DEFAULT_PORT}/redoc")
    print(f"  OpenAPI:    http://{DEFAULT_HOST}:{DEFAULT_PORT}/openapi.json")
    print()
    print("=" * 70)
    print()

    uvicorn.run(
        app,
        host=DEFAULT_HOST,
        port=DEFAULT_PORT,
        log_level="info",
        access_log=True,
        log_config={
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "access": {
                    "()": "uvicorn.logging.AccessFormatter",
                    "fmt": '%(asctime)s %(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
                    "datefmt": "%Y-%m-%d %H:%M:%S",
                },
                "default": {
                    "()": "uvicorn.logging.DefaultFormatter",
                    "fmt": "%(asctime)s %(levelprefix)s %(message)s",
                    "datefmt": "%Y-%m-%d %H:%M:%S",
                },
            },
            "handlers": {
                "access": {
                    "formatter": "access",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stderr",
                },
                "default": {
                    "formatter": "default",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stderr",
                },
            },
            "loggers": {
                "uvicorn": {"handlers": ["default"], "level": "INFO"},
                "uvicorn.error": {"level": "INFO"},
                "uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False},
                "auth": {"handlers": ["default"], "level": "WARNING", "propagate": False},
            },
        },
    )
