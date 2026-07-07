#!/usr/bin/env python3
"""
Divine API - Western Astrology MCP Server

Official MCP server by Divine API for Western Astrology services.
Provides 56 tools for Natal Charts, Synastry, Transits, Composite Charts,
Progressions, Returns, Prenatal analysis, and Advanced Natal techniques.

Setup:
    1. Get your API key and auth token from https://divineapi.com/api-keys
    2. Set environment variables: DIVINE_API_KEY and DIVINE_AUTH_TOKEN
    3. Add to your MCP client configuration (Claude Desktop, Cursor, etc.)

Documentation: https://developers.divineapi.com/western-api
"""

import base64
import json
import os
import secrets
import sys
import time

import httpx
import jwt
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl, BaseModel, Field, ConfigDict, field_validator

# ──────────────────────────────────────────────
# Server Initialization
# ──────────────────────────────────────────────

_TRANSPORT = os.environ.get("MCP_TRANSPORT", "stdio")
_MCP_HOST = os.environ.get("MCP_HOST", "mcp.divineapi.com")
_JWT_SECRET = os.environ.get("MCP_JWT_SECRET", secrets.token_hex(32))

_transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=[
        f"{_MCP_HOST}",
        f"{_MCP_HOST}:*",
        "127.0.0.1:*",
        "localhost:*",
    ],
) if _TRANSPORT == "http" else None


# ──────────────────────────────────────────────
# OAuth Provider -maps OAuth Client ID/Secret to Divine API credentials
# ──────────────────────────────────────────────


class DivineOAuthProvider(OAuthAuthorizationServerProvider):
    """OAuth provider that uses Divine API Key as client_id and Auth Token as client_secret."""

    def __init__(self, jwt_secret: str):
        self._jwt_secret = jwt_secret
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._auth_codes: dict[str, dict] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        if client_id in self._clients:
            return self._clients[client_id]
        auto_client = OAuthClientInformationFull(
            client_id=client_id,
            client_secret=None,
            redirect_uris=['https://claude.ai/oauth/callback', 'https://app.claude.ai/oauth/callback', 'https://claude.ai/api/mcp/auth_callback', 'https://app.claude.ai/api/mcp/auth_callback'],
            grant_types=['authorization_code', 'refresh_token'],
            response_types=['code'],
            token_endpoint_auth_method='client_secret_post',
            scope='astrology',
        )
        self._clients[client_id] = auto_client
        return auto_client

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self._clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        pending_id = secrets.token_urlsafe(16)
        self._pending_auths = getattr(self, "_pending_auths", {})
        self._pending_auths[pending_id] = {
            "client_id": client.client_id,
            "code_challenge": params.code_challenge,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "scopes": params.scopes or [],
            "state": params.state,
        }
        return f"/divine-login?pending={pending_id}"

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str) -> AuthorizationCode | None:
        data = self._auth_codes.get(authorization_code)
        if not data or data["client_id"] != client.client_id:
            return None
        if time.time() > data["expires_at"]:
            return None
        return AuthorizationCode(
            code=authorization_code,
            scopes=data["scopes"],
            expires_at=data["expires_at"],
            client_id=data["client_id"],
            code_challenge=data["code_challenge"],
            redirect_uri=AnyUrl(data["redirect_uri"]),
            redirect_uri_provided_explicitly=data["redirect_uri_provided_explicitly"],
        )

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode) -> OAuthToken:
        data = self._auth_codes.pop(authorization_code.code, None)
        if not data:
            raise TokenError(error="invalid_grant", error_description="Authorization code not found")

        payload = {
            "divine_api_key": data.get("divine_api_key", ""),
            "divine_auth_token": data.get("divine_auth_token", ""),
            "exp": int(time.time()) + 86400 * 30,
            "iat": int(time.time()),
        }
        access_token = jwt.encode(payload, self._jwt_secret, algorithm="HS256")

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=86400 * 30,
        )

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        return None

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        raise TokenError(error="unsupported_grant_type", error_description="Refresh tokens not supported")

    async def load_access_token(self, token: str) -> AccessToken | None:
        try:
            payload = jwt.decode(token, self._jwt_secret, algorithms=["HS256"])
            return AccessToken(
                token=token,
                client_id=payload["divine_api_key"],
                scopes=[],
                expires_at=payload.get("exp"),
                resource=None,
            )
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        pass


# Build auth settings for HTTP mode
_auth_settings = None
_auth_provider = None
if _TRANSPORT == "http":
    _auth_provider = DivineOAuthProvider(_JWT_SECRET)
    _auth_settings = AuthSettings(
        issuer_url=f"https://{_MCP_HOST}/western",
        resource_server_url=f"https://{_MCP_HOST}/western",
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=["astrology"],
            default_scopes=["astrology"],
        ),
        revocation_options=RevocationOptions(enabled=True),
        required_scopes=[],
    )

mcp = FastMCP(
    "divineapi_western_astrology_mcp",
    stateless_http=(_TRANSPORT == "http"),
    transport_security=_transport_security,
    auth=_auth_settings,
    auth_server_provider=_auth_provider,
)

# ──────────────────────────────────────────────
# Configuration -Base URLs for API hosts
# ──────────────────────────────────────────────

API_HOST_4 = "https://astroapi-4.divineapi.com"
API_HOST_8 = "https://astroapi-8.divineapi.com"

DIVINE_API_KEY = os.environ.get("DIVINE_API_KEY", "")
DIVINE_AUTH_TOKEN = os.environ.get("DIVINE_AUTH_TOKEN", "")

if _TRANSPORT == "stdio" and (not DIVINE_API_KEY or not DIVINE_AUTH_TOKEN):
    print(
        "WARNING: DIVINE_API_KEY and DIVINE_AUTH_TOKEN environment variables are required. "
        "Get yours at https://divineapi.com/api-keys",
        file=sys.stderr,
    )


def _get_credentials(ctx: Context | None = None) -> tuple[str, str]:
    """Extract Divine API credentials from JWT Bearer token, request headers, or env vars."""
    api_key = DIVINE_API_KEY
    auth_token = DIVINE_AUTH_TOKEN
    if ctx:
        try:
            request = getattr(ctx.request_context, "request", None)
            if request and hasattr(request, "headers"):
                auth_header = request.headers.get("authorization", "")
                if auth_header.startswith("Bearer "):
                    token = auth_header[7:]
                    try:
                        payload = jwt.decode(token, _JWT_SECRET, algorithms=["HS256"])
                        api_key = payload.get("divine_api_key", api_key)
                        auth_token = payload.get("divine_auth_token", auth_token)
                    except Exception:
                        pass
                api_key = request.headers.get("x-divine-api-key", api_key)
                auth_token = request.headers.get("x-divine-auth-token", auth_token)
        except Exception:
            pass
    if not api_key or not auth_token:
        raise ValueError(
            "Divine API credentials required. "
            "Set X-Divine-Api-Key and X-Divine-Auth-Token headers, "
            "or DIVINE_API_KEY and DIVINE_AUTH_TOKEN environment variables. "
            "Get yours at https://divineapi.com/api-keys"
        )
    return api_key, auth_token

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

VALID_GENDERS = {"male", "female"}

# Friendly house-system names mapped to the Swiss Ephemeris single-letter
# codes the live API accepts. The API rejects word values like "placidus"
# on astroapi-4 and silently ignores them on astroapi-8, so every payload
# must send the letter code.
HOUSE_SYSTEM_MAP = {
    "placidus": "P",
    "koch": "K",
    "porphyry": "O",
    "regiomontanus": "R",
    "campanus": "C",
    "equal": "E",
    "whole-sign": "W",
    "whole_sign": "W",
    "wholesign": "W",
    "morinus": "M",
    "alcabitius": "B",
}
VALID_HOUSE_SYSTEM_LETTERS = set(HOUSE_SYSTEM_MAP.values())
HOUSE_SYSTEM_FRIENDLY_NAMES = "placidus, koch, porphyry, regiomontanus, campanus, equal, whole-sign, morinus, alcabitius"

VALID_DOMINANTS_METHODS = {"TRADITIONAL", "MODERN"}

TOOL_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}


def _resolve_house_system(value: str) -> str:
    """Map a friendly house-system name to its single-letter API code.

    Accepts friendly names case-insensitively (e.g. 'placidus', 'Whole-Sign')
    and already-valid single letters (passed through unchanged). Raises
    ValueError for anything else.
    """
    hs = (value or "").strip()
    if not hs:
        return "P"
    if hs.upper() in VALID_HOUSE_SYSTEM_LETTERS:
        return hs.upper()
    mapped = HOUSE_SYSTEM_MAP.get(hs.lower())
    if mapped:
        return mapped
    raise ValueError(
        f"Invalid house_system '{value}'. Must be one of: {HOUSE_SYSTEM_FRIENDLY_NAMES} "
        f"(or a single-letter code: {', '.join(sorted(VALID_HOUSE_SYSTEM_LETTERS))})"
    )


def _apply_house_system(payload: dict, house_system: str | None) -> str | None:
    """Validate house_system, map it to a letter code, and add it to the payload.

    Returns an error message string on invalid input, else None.
    """
    if house_system:
        try:
            payload["house_system"] = _resolve_house_system(house_system)
        except ValueError as e:
            return f"Error: {e}"
    return None


def _apply_dominants_method(payload: dict, method: str) -> str | None:
    """Validate the dominants calculation method and add it to the payload.

    Returns an error message string on invalid input, else None.
    """
    m = (method or "").upper().strip()
    if m not in VALID_DOMINANTS_METHODS:
        return f"Error: Invalid method '{method}'. Must be one of: {', '.join(sorted(VALID_DOMINANTS_METHODS))}"
    payload["method"] = m
    return None

# ──────────────────────────────────────────────
# Pydantic Models
# ──────────────────────────────────────────────


class WesternNatalInput(BaseModel):
    """Input for Western natal chart API calls. Requires full birth details including time and location."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    full_name: str = Field(..., description="Full name of the person (e.g., 'John Smith')", min_length=1, max_length=200)
    day: str = Field(..., description="Birth day (e.g., '24')", min_length=1, max_length=2)
    month: str = Field(..., description="Birth month (e.g., '05')", min_length=1, max_length=2)
    year: str = Field(..., description="Birth year (e.g., '1990')", min_length=4, max_length=4)
    hour: str = Field(..., description="Birth hour in 24h format (e.g., '14')", min_length=1, max_length=2)
    min: str = Field(..., description="Birth minute (e.g., '40')", min_length=1, max_length=2)
    sec: str = Field(default="0", description="Birth second (e.g., '0')", max_length=2)
    gender: str = Field(..., description="Gender: 'male' or 'female'")
    place: str = Field(..., description="Birth place (e.g., 'New York')", min_length=1, max_length=200)
    lat: str = Field(..., description="Latitude of birth place (e.g., '40.7128')")
    lon: str = Field(..., description="Longitude of birth place (e.g., '-74.0060')")
    tzone: str = Field(..., description="Timezone offset from UTC (e.g., '-5' for EST)")
    lan: str = Field(default="en", description="Language code for response (default 'en')")
    house_system: str = Field(default="placidus", validate_default=True, description="House system (default 'placidus'). Options: placidus, koch, porphyry, regiomontanus, campanus, equal, whole-sign, morinus, alcabitius (or the single-letter codes B, C, E, K, M, O, P, R, W)")

    @field_validator("gender")
    @classmethod
    def validate_gender(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in VALID_GENDERS:
            raise ValueError(f"Gender must be 'male' or 'female', got '{v}'")
        return v

    @field_validator("house_system")
    @classmethod
    def validate_house_system(cls, v: str) -> str:
        return _resolve_house_system(v)


class WesternSynastryInput(BaseModel):
    """Input for Western synastry/compatibility API calls. Requires birth details for both persons."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    # Person 1
    p1_full_name: str = Field(..., description="Full name of person 1", min_length=1)
    p1_day: str = Field(..., description="Birth day of person 1 (e.g., '24')")
    p1_month: str = Field(..., description="Birth month of person 1 (e.g., '05')")
    p1_year: str = Field(..., description="Birth year of person 1 (e.g., '1998')")
    p1_hour: str = Field(..., description="Birth hour of person 1 in 24h format (e.g., '14')")
    p1_min: str = Field(..., description="Birth minute of person 1 (e.g., '40')")
    p1_sec: str = Field(default="0", description="Birth second of person 1")
    p1_gender: str = Field(..., description="Gender of person 1: 'male' or 'female'")
    p1_place: str = Field(..., description="Birth place of person 1 (e.g., 'New York')")
    p1_lat: str = Field(..., description="Latitude of person 1's birth place (e.g., '40.7128')")
    p1_lon: str = Field(..., description="Longitude of person 1's birth place (e.g., '-74.0060')")
    p1_tzone: str = Field(..., description="Timezone of person 1 (e.g., '-5')")

    # Person 2
    p2_full_name: str = Field(..., description="Full name of person 2", min_length=1)
    p2_day: str = Field(..., description="Birth day of person 2 (e.g., '15')")
    p2_month: str = Field(..., description="Birth month of person 2 (e.g., '08')")
    p2_year: str = Field(..., description="Birth year of person 2 (e.g., '1995')")
    p2_hour: str = Field(..., description="Birth hour of person 2 in 24h format (e.g., '10')")
    p2_min: str = Field(..., description="Birth minute of person 2 (e.g., '30')")
    p2_sec: str = Field(default="0", description="Birth second of person 2")
    p2_gender: str = Field(..., description="Gender of person 2: 'male' or 'female'")
    p2_place: str = Field(..., description="Birth place of person 2 (e.g., 'London')")
    p2_lat: str = Field(..., description="Latitude of person 2's birth place (e.g., '51.5074')")
    p2_lon: str = Field(..., description="Longitude of person 2's birth place (e.g., '-0.1278')")
    p2_tzone: str = Field(..., description="Timezone of person 2 (e.g., '0')")

    lan: str = Field(default="en", description="Language code for response (default 'en')")
    house_system: str = Field(default="placidus", validate_default=True, description="House system (default 'placidus'). Options: placidus, koch, porphyry, regiomontanus, campanus, equal, whole-sign, morinus, alcabitius (or the single-letter codes B, C, E, K, M, O, P, R, W)")

    @field_validator("house_system")
    @classmethod
    def validate_house_system(cls, v: str) -> str:
        return _resolve_house_system(v)


class WesternTransitPlanetInput(BaseModel):
    """Input for planet-specific transit API calls. Requires planet name, month/year, and location."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    planet: str = Field(..., description="Planet name (e.g., 'mercury', 'venus', 'mars', 'jupiter', 'saturn', 'uranus', 'neptune', 'pluto')")
    month: str = Field(..., description="Month number (e.g., '05')", min_length=1, max_length=2)
    year: str = Field(..., description="Year (e.g., '2025')", min_length=4, max_length=4)
    place: str = Field(..., description="Place name (e.g., 'New York')", min_length=1, max_length=200)
    lat: str = Field(..., description="Latitude (e.g., '40.7128')")
    lon: str = Field(..., description="Longitude (e.g., '-74.0060')")
    tzone: str = Field(..., description="Timezone offset from UTC (e.g., '-5')")


class WesternFullTransitInput(BaseModel):
    """Input for full transit API calls requiring both natal and transit date/location."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    full_name: str = Field(..., description="Full name of the person", min_length=1, max_length=200)
    day: str = Field(..., description="Birth day (e.g., '24')", min_length=1, max_length=2)
    month: str = Field(..., description="Birth month (e.g., '05')", min_length=1, max_length=2)
    year: str = Field(..., description="Birth year (e.g., '1990')", min_length=4, max_length=4)
    hour: str = Field(..., description="Birth hour in 24h format (e.g., '14')", min_length=1, max_length=2)
    min: str = Field(..., description="Birth minute (e.g., '40')", min_length=1, max_length=2)
    sec: str = Field(default="0", description="Birth second", max_length=2)
    gender: str = Field(..., description="Gender: 'male' or 'female'")
    place: str = Field(..., description="Birth place (e.g., 'New Delhi')", min_length=1, max_length=200)
    lat: str = Field(..., description="Latitude (e.g., '28.7041')")
    lon: str = Field(..., description="Longitude (e.g., '77.1025')")
    tzone: str = Field(..., description="Timezone offset (e.g., '5.5')")
    transit_day: str = Field(..., description="Transit day (e.g., '5')", min_length=1, max_length=2)
    transit_month: str = Field(..., description="Transit month (e.g., '08')", min_length=1, max_length=2)
    transit_year: str = Field(..., description="Transit year (e.g., '2025')", min_length=4, max_length=4)
    transit_hour: str = Field(default="0", description="Transit hour (e.g., '12')", max_length=2)
    transit_min: str = Field(default="0", description="Transit minute", max_length=2)
    transit_sec: str = Field(default="0", description="Transit second", max_length=2)
    transit_place: str = Field(..., description="Transit location (e.g., 'New Delhi')", min_length=1, max_length=200)
    transit_lat: str = Field(..., description="Transit latitude (e.g., '28.7041')")
    transit_lon: str = Field(..., description="Transit longitude (e.g., '77.1025')")
    transit_tzone: str = Field(..., description="Transit timezone (e.g., '5.5')")


class WesternMoonPhaseCalendarInput(BaseModel):
    """Input for the moon phase calendar API: month, year, and location only."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    month: str = Field(..., description="Month number (e.g., '05' for May)", min_length=1, max_length=2)
    year: str = Field(..., description="Year (e.g., '2025')", min_length=4, max_length=4)
    place: str = Field(..., description="Place name (e.g., 'New York')", min_length=1, max_length=200)
    lat: str = Field(..., description="Latitude of the place (e.g., '40.7128')")
    lon: str = Field(..., description="Longitude of the place (e.g., '-74.0060')")
    tzone: str = Field(..., description="Timezone offset from UTC (e.g., '-5' for EST)")
    lan: str = Field(default="en", description="Language code for response (default 'en')")
    full_name: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")
    day: str | None = Field(default=None, description="Deprecated: this endpoint is month-scoped and ignores day. Accepted for backward compatibility, not sent to the API.")
    hour: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")
    min: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")
    sec: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")
    gender: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")
    house_system: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")


class WesternFixedStarsListInput(BaseModel):
    """Input for the fixed stars list API. The endpoint takes no parameters; every field here is deprecated and ignored."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    full_name: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")
    day: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")
    month: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")
    year: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")
    hour: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")
    min: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")
    sec: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")
    gender: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")
    place: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")
    lat: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")
    lon: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")
    tzone: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")
    lan: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")
    house_system: str | None = Field(default=None, description="Deprecated: ignored by this endpoint. Accepted for backward compatibility, not sent to the API.")


# ──────────────────────────────────────────────
# Shared API Client
# ──────────────────────────────────────────────


async def _call_divine_api(
    endpoint: str,
    payload: dict,
    base_url: str = API_HOST_4,
    api_key: str | None = None,
    auth_token: str | None = None,
) -> str:
    """Make a POST request to Divine API and return formatted JSON response.

    Raises ToolError on any failure (non-2xx, network error, or an upstream
    error envelope returned with HTTP 200) so MCP clients see isError: true
    instead of a success result whose text merely contains 'Error: ...'.
    """
    payload["api_key"] = api_key or DIVINE_API_KEY
    clean_payload = {k: v for k, v in payload.items() if v is not None}
    url = f"{base_url}{endpoint}"
    bearer = auth_token or DIVINE_AUTH_TOKEN

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                headers={"Authorization": f"Bearer {bearer}"},
                data=clean_payload,
                timeout=30.0,
            )
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as e:
        raise ToolError(_handle_http_error(e)) from e
    except httpx.TimeoutException as e:
        raise ToolError("Request timed out. The Divine API server may be slow. Please try again.") from e
    except httpx.ConnectError as e:
        raise ToolError("Could not connect to Divine API. Please check your internet connection.") from e
    except Exception as e:
        raise ToolError(f"Unexpected error - {type(e).__name__}: {str(e)}") from e

    # Some endpoints return HTTP 200 with an error envelope in the body.
    # Two shapes are used across the Divine API hosts:
    #   astroapi-4 (legacy):  {"success": 2, "msg": ["Please enter valid ..."]}
    #   astroapi-8 (newer):   {"status": "error", "message": "...", ...}
    # A successful legacy response is success==1; newer success omits "success".
    if isinstance(data, dict):
        if data.get("status") == "error" or ("success" in data and str(data.get("success")) != "1"):
            msg = data.get("message") or data.get("msg") or "Divine API returned an error."
            if isinstance(msg, list):
                msg = "; ".join(str(m) for m in msg)
            raise ToolError(f"Divine API error: {msg}")

    return json.dumps(data, indent=2, ensure_ascii=False)


def _handle_http_error(e: httpx.HTTPStatusError) -> str:
    """Return actionable error messages for HTTP errors."""
    status = e.response.status_code
    if status == 401:
        return (
            "Error: Authentication failed (401). "
            "Please check your DIVINE_API_KEY and DIVINE_AUTH_TOKEN environment variables. "
            "Get your credentials at https://divineapi.com/api-keys"
        )
    elif status == 403:
        return (
            "Error: Access forbidden (403). "
            "Your API plan may not include Western Astrology APIs. "
            "Check your subscription at https://divineapi.com/pricing"
        )
    elif status == 429:
        return (
            "Error: Rate limit exceeded (429). "
            "You've exceeded your request limit or are sending too many concurrent requests. "
            "Please wait and try again."
        )
    elif status == 404:
        return "Error: Endpoint not found (404). This API endpoint may not be available on your plan."
    else:
        body = ""
        try:
            body = e.response.text[:500]
        except Exception:
            pass
        return f"Error: API returned status {status}. Response: {body}"


# ──────────────────────────────────────────────
# Payload Helpers
# ──────────────────────────────────────────────


def _natal_payload(params: WesternNatalInput) -> dict:
    return {
        "full_name": params.full_name,
        "day": params.day,
        "month": params.month,
        "year": params.year,
        "hour": params.hour,
        "min": params.min,
        "sec": params.sec,
        "gender": params.gender,
        "place": params.place,
        "lat": params.lat,
        "lon": params.lon,
        "tzone": params.tzone,
        "lan": params.lan,
        "house_system": params.house_system,
    }


def _synastry_payload(params: WesternSynastryInput) -> dict:
    return {
        "p1_full_name": params.p1_full_name,
        "p1_day": params.p1_day,
        "p1_month": params.p1_month,
        "p1_year": params.p1_year,
        "p1_hour": params.p1_hour,
        "p1_min": params.p1_min,
        "p1_sec": params.p1_sec,
        "p1_gender": params.p1_gender,
        "p1_place": params.p1_place,
        "p1_lat": params.p1_lat,
        "p1_lon": params.p1_lon,
        "p1_tzone": params.p1_tzone,
        "p2_full_name": params.p2_full_name,
        "p2_day": params.p2_day,
        "p2_month": params.p2_month,
        "p2_year": params.p2_year,
        "p2_hour": params.p2_hour,
        "p2_min": params.p2_min,
        "p2_sec": params.p2_sec,
        "p2_gender": params.p2_gender,
        "p2_place": params.p2_place,
        "p2_lat": params.p2_lat,
        "p2_lon": params.p2_lon,
        "p2_tzone": params.p2_tzone,
        "lan": params.lan,
        "house_system": params.house_system,
    }


def _transit_planet_payload(params: WesternTransitPlanetInput) -> dict:
    return {
        "planet": params.planet,
        "month": params.month,
        "year": params.year,
        "place": params.place,
        "lat": params.lat,
        "lon": params.lon,
        "tzone": params.tzone,
    }


def _full_transit_payload(params) -> dict:
    return {
        "full_name": params.full_name, "day": params.day, "month": params.month,
        "year": params.year, "hour": params.hour, "min": params.min,
        "sec": params.sec, "gender": params.gender, "place": params.place,
        "lat": params.lat, "lon": params.lon, "tzone": params.tzone,
        "transit_day": params.transit_day, "transit_month": params.transit_month,
        "transit_year": params.transit_year, "transit_hour": params.transit_hour,
        "transit_min": params.transit_min, "transit_sec": params.transit_sec,
        "transit_place": params.transit_place, "transit_lat": params.transit_lat,
        "transit_lon": params.transit_lon, "transit_tzone": params.transit_tzone,
    }


# ══════════════════════════════════════════════
# NATAL TOOLS (10) - astroapi-4.divineapi.com
# ══════════════════════════════════════════════


@mcp.tool(name="divine_western_planetary_positions", annotations=TOOL_ANNOTATIONS)
async def divine_western_planetary_positions(params: WesternNatalInput, ctx: Context) -> str:
    """Get planetary positions in the Western natal chart.

    Returns positions of Sun, Moon, Mercury, Venus, Mars, Jupiter, Saturn,
    Uranus, Neptune, Pluto with sign, degree, and house placement.
    For a complete natal reading, also call divine_western_house_cusps,
    divine_western_aspect_table, and divine_western_natal_insights in parallel.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/planetary-positions", _natal_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_house_cusps", annotations=TOOL_ANNOTATIONS)
async def divine_western_house_cusps(params: WesternNatalInput, ctx: Context) -> str:
    """Get house cusps for the Western natal chart.

    Returns the degree and sign of each of the 12 house cusps based on the
    selected house system (Placidus, Koch, Equal, Whole Sign, etc.).
    Houses represent different life areas: identity, finances, communication,
    home, creativity, health, partnerships, transformation, philosophy,
    career, community, and spirituality.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/house-cusps", _natal_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_aspect_table", annotations=TOOL_ANNOTATIONS)
async def divine_western_aspect_table(params: WesternNatalInput, ctx: Context) -> str:
    """Get the aspect table for the Western natal chart.

    Returns all major and minor aspects (conjunctions, oppositions, trines,
    squares, sextiles, quincunxes, semi-sextiles, etc.) between planets.
    Aspects reveal how planetary energies interact, showing areas of harmony,
    tension, and growth in the native's life.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v2/aspect-table", _natal_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_natal_wheel_chart", annotations=TOOL_ANNOTATIONS)
async def divine_western_natal_wheel_chart(
    params: WesternNatalInput,
    ctx: Context,
    show_symbol: str | None = None,
    wheel_lines: str | None = None,
    wheel_color: str | None = None,
    text_color: str | None = None,
    outter_background: str | None = None,
    wheel_background: str | None = None,
) -> str:
    """Generate a visual natal wheel chart image.

    Returns an image URL of the natal chart wheel showing planet placements,
    house cusps, and zodiac signs in a traditional circular format.
    Customize colors and display options with optional parameters.
    """
    api_key, auth_token = _get_credentials(ctx)
    payload = _natal_payload(params)
    if show_symbol is not None:
        payload["show_symbol"] = show_symbol
    if wheel_lines is not None:
        payload["wheel_lines"] = wheel_lines
    if wheel_color is not None:
        payload["wheel_color"] = wheel_color
    if text_color is not None:
        payload["text_color"] = text_color
    if outter_background is not None:
        payload["outter_background"] = outter_background
    if wheel_background is not None:
        payload["wheel_background"] = wheel_background
    return await _call_divine_api("/western-api/v2/natal-wheel-chart", payload, API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_general_sign_report", annotations=TOOL_ANNOTATIONS)
async def divine_western_general_sign_report(
    planet: str,
    full_name: str, day: str, month: str, year: str, hour: str, min: str,
    gender: str, place: str, lat: str, lon: str, tzone: str,
    ctx: Context,
    sec: str = "0", lan: str = "en", house_system: str = "placidus",
) -> str:
    """Get a general sign report for a specific planet in the natal chart.

    Returns an interpretive reading of the specified planet's sign placement.
    For example, 'sun' returns the Sun sign interpretation, 'moon' the Moon
    sign reading, 'venus' the Venus sign meaning for love and values, etc.
    Planet options: sun, moon, mercury, venus, mars, jupiter, saturn, uranus, neptune, pluto.
    """
    api_key, auth_token = _get_credentials(ctx)
    payload = {
        "full_name": full_name, "day": day, "month": month, "year": year,
        "hour": hour, "min": min, "sec": sec, "gender": gender,
        "place": place, "lat": lat, "lon": lon, "tzone": tzone,
        "lan": lan,
    }
    err = _apply_house_system(payload, house_system)
    if err:
        return err
    return await _call_divine_api(f"/western-api/v2/general-sign-report/{planet}", payload, API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_general_house_report", annotations=TOOL_ANNOTATIONS)
async def divine_western_general_house_report(
    planet: str,
    full_name: str, day: str, month: str, year: str, hour: str, min: str,
    gender: str, place: str, lat: str, lon: str, tzone: str,
    ctx: Context,
    sec: str = "0", lan: str = "en", house_system: str = "placidus",
) -> str:
    """Get a general house report for a specific planet in the natal chart.

    Returns an interpretive reading of the specified planet's house placement.
    Reveals how the planet's energy manifests in a particular life area.
    For example, Venus in the 7th house indicates partnership-oriented love.
    Planet options: sun, moon, mercury, venus, mars, jupiter, saturn, uranus, neptune, pluto.
    """
    api_key, auth_token = _get_credentials(ctx)
    payload = {
        "full_name": full_name, "day": day, "month": month, "year": year,
        "hour": hour, "min": min, "sec": sec, "gender": gender,
        "place": place, "lat": lat, "lon": lon, "tzone": tzone,
        "lan": lan,
    }
    err = _apply_house_system(payload, house_system)
    if err:
        return err
    return await _call_divine_api(f"/western-api/v2/general-house-report/{planet}", payload, API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_moon_phases", annotations=TOOL_ANNOTATIONS)
async def divine_western_moon_phases(params: WesternNatalInput, ctx: Context) -> str:
    """Get natal Moon phase information for the birth chart.

    Returns the Moon phase at the time of birth (New Moon, Waxing Crescent,
    First Quarter, Waxing Gibbous, Full Moon, Waning Gibbous, Last Quarter,
    Waning Crescent) and its astrological significance for personality and
    life purpose.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v2/moon-phases", _natal_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_ascendant_report", annotations=TOOL_ANNOTATIONS)
async def divine_western_ascendant_report(params: WesternNatalInput, ctx: Context) -> str:
    """Get the Ascendant (Rising Sign) report for the birth chart.

    Returns a detailed interpretation of the Ascendant sign, which represents
    the persona, physical appearance, and first impressions. The Ascendant is
    the zodiac sign on the eastern horizon at the moment of birth and is one
    of the most personal points in the chart.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v2/ascendant-report", _natal_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_moon_phase_calendar", annotations=TOOL_ANNOTATIONS)
async def divine_western_moon_phase_calendar(params: WesternMoonPhaseCalendarInput, ctx: Context) -> str:
    """Get a Moon phase calendar for a given month, year, and location.

    Returns a calendar of Moon phases showing New Moons, Full Moons, and
    quarter phases. Useful for planning activities aligned with lunar cycles,
    understanding emotional rhythms, and timing important decisions.
    Only month, year, and location are needed; birth details are not used.
    """
    api_key, auth_token = _get_credentials(ctx)
    payload = {
        "month": params.month,
        "year": params.year,
        "place": params.place,
        "lat": params.lat,
        "lon": params.lon,
        "tzone": params.tzone,
        "lan": params.lan,
    }
    return await _call_divine_api("/western-api/v1/moon-phase-calendar", payload, API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_natal_insights", annotations=TOOL_ANNOTATIONS)
async def divine_western_natal_insights(params: WesternNatalInput, ctx: Context) -> str:
    """Get comprehensive natal insights and personality analysis.

    Returns a detailed interpretive report covering the overall chart pattern,
    dominant elements, modalities, key planetary placements, and synthesized
    personality insights. Provides a holistic view of the native's strengths,
    challenges, and life themes.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/natal-insights", _natal_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


# ══════════════════════════════════════════════
# SYNASTRY TOOLS (13) -astroapi-4.divineapi.com
# ══════════════════════════════════════════════


@mcp.tool(name="divine_western_synastry_planetary_positions", annotations=TOOL_ANNOTATIONS)
async def divine_western_synastry_planetary_positions(params: WesternSynastryInput, ctx: Context) -> str:
    """Get planetary positions for both persons in synastry analysis.

    Returns the positions of all planets for both individuals, showing how
    their charts overlay. For a complete compatibility reading, also call
    divine_western_synastry_aspect, divine_western_synastry_harmonious_reading,
    and divine_western_synastry_physical_compat in parallel.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/synastry/planetary-positions", _synastry_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_synastry_house_cusps", annotations=TOOL_ANNOTATIONS)
async def divine_western_synastry_house_cusps(params: WesternSynastryInput, ctx: Context) -> str:
    """Get house cusps for both persons in synastry analysis.

    Returns the house cusps for each individual's chart, enabling comparison
    of how one person's planets fall into the other's houses. This reveals
    which life areas are activated in the relationship.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/synastry/house-cusps", _synastry_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_synastry_natal_wheel_chart", annotations=TOOL_ANNOTATIONS)
async def divine_western_synastry_natal_wheel_chart(params: WesternSynastryInput, ctx: Context) -> str:
    """Generate a bi-wheel synastry chart image for two persons.

    Returns an image URL showing both natal charts overlaid in a bi-wheel
    format, with one person's chart on the inner wheel and the other on
    the outer wheel for visual aspect analysis.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v2/synastry/natal-wheel-chart", _synastry_payload(params), API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_synastry_aspect", annotations=TOOL_ANNOTATIONS)
async def divine_western_synastry_aspect(params: WesternSynastryInput, ctx: Context) -> str:
    """Get inter-chart aspects between two persons in synastry.

    Returns all aspects formed between one person's planets and the other's,
    including conjunctions, trines, squares, oppositions, and sextiles.
    These cross-chart aspects are the foundation of relationship astrology,
    revealing attraction, friction, and compatibility.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v2/synastry/aspect-table", _synastry_payload(params), API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_synastry_harmonious_reading", annotations=TOOL_ANNOTATIONS)
async def divine_western_synastry_harmonious_reading(params: WesternSynastryInput, ctx: Context) -> str:
    """Get harmonious aspect reading for a synastry pair.

    Returns interpretations of all harmonious aspects (trines, sextiles,
    conjunctions with benefics) between the two charts. These aspects
    indicate natural ease, mutual support, and areas where the relationship
    flows effortlessly.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/synastry/harmonious-aspect-reading", _synastry_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_synastry_conflicting_reading", annotations=TOOL_ANNOTATIONS)
async def divine_western_synastry_conflicting_reading(params: WesternSynastryInput, ctx: Context) -> str:
    """Get conflicting aspect reading for a synastry pair.

    Returns interpretations of conflicting aspects (squares, oppositions)
    between the two charts. These aspects indicate areas of friction,
    disagreement, and challenge that require conscious effort and compromise
    to navigate successfully.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/synastry/conflicting-aspect-reading", _synastry_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_synastry_contrasting_reading", annotations=TOOL_ANNOTATIONS)
async def divine_western_synastry_contrasting_reading(params: WesternSynastryInput, ctx: Context) -> str:
    """Get contrasting aspect reading for a synastry pair.

    Returns interpretations of contrasting aspects (quincunxes, semi-sextiles)
    between the two charts. These aspects indicate areas where the partners
    have fundamentally different approaches that require adjustment, adaptation,
    and willingness to accept differences.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/synastry/contrasting-aspect-reading", _synastry_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_synastry_intense_reading", annotations=TOOL_ANNOTATIONS)
async def divine_western_synastry_intense_reading(params: WesternSynastryInput, ctx: Context) -> str:
    """Get intense aspect reading for a synastry pair.

    Returns interpretations of intense aspects (Pluto aspects, Mars-Saturn,
    Sun-Pluto contacts) between the two charts. These aspects indicate deep
    transformative dynamics, power struggles, obsession, and profound
    psychological influence between partners.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/synastry/intense-aspect-reading", _synastry_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_synastry_physical_compat", annotations=TOOL_ANNOTATIONS)
async def divine_western_synastry_physical_compat(params: WesternSynastryInput, ctx: Context) -> str:
    """Get physical compatibility analysis for a synastry pair.

    Returns an assessment of physical attraction and chemistry between two
    persons based on Mars, Venus, Ascendant, and 5th/8th house overlays.
    Evaluates the strength of physical magnetism and bodily harmony.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v2/synastry/physical-compatibility", _synastry_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_synastry_emotional_compat", annotations=TOOL_ANNOTATIONS)
async def divine_western_synastry_emotional_compat(params: WesternSynastryInput, ctx: Context) -> str:
    """Get emotional compatibility analysis for a synastry pair.

    Returns an assessment of emotional connection and nurturing patterns
    between two persons based on Moon contacts, Cancer/4th house overlays,
    and water sign emphasis. Evaluates how partners meet each other's
    emotional needs and provide comfort.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v2/synastry/emotional-compatibility", _synastry_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_synastry_sexual_compat", annotations=TOOL_ANNOTATIONS)
async def divine_western_synastry_sexual_compat(params: WesternSynastryInput, ctx: Context) -> str:
    """Get sexual compatibility analysis for a synastry pair.

    Returns an assessment of sexual chemistry and intimate compatibility
    based on Mars-Venus aspects, 8th house overlays, Pluto contacts, and
    Scorpio emphasis. Evaluates passion, desire, and intimate harmony
    between partners.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v2/synastry/sexual-compatibility", _synastry_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_synastry_spiritual_compat", annotations=TOOL_ANNOTATIONS)
async def divine_western_synastry_spiritual_compat(params: WesternSynastryInput, ctx: Context) -> str:
    """Get spiritual compatibility analysis for a synastry pair.

    Returns an assessment of spiritual connection and shared higher purpose
    between two persons based on Neptune contacts, 9th/12th house overlays,
    and Jupiter aspects. Evaluates shared beliefs, transcendent experiences,
    and soul-level resonance.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v2/synastry/spiritual-compatibility", _synastry_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_synastry_financial_compat", annotations=TOOL_ANNOTATIONS)
async def divine_western_synastry_financial_compat(params: WesternSynastryInput, ctx: Context) -> str:
    """Get financial compatibility analysis for a synastry pair.

    Returns an assessment of financial harmony and shared material values
    between two persons based on 2nd/8th house overlays, Venus-Jupiter
    aspects, and Saturn contacts. Evaluates attitudes toward money, spending
    habits, and potential for shared wealth building.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v2/synastry/financial-compatibility", _synastry_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


# ══════════════════════════════════════════════
# TRANSIT TOOLS (11) - astroapi-4 & astroapi-8
# ══════════════════════════════════════════════


@mcp.tool(name="divine_western_transit_basic", annotations=TOOL_ANNOTATIONS)
async def divine_western_transit_basic(
    params: WesternNatalInput,
    ctx: Context,
    transit_day: str = Field(..., description="Transit day (e.g., '10')"),
    transit_month: str = Field(..., description="Transit month (e.g., '02')"),
    transit_year: str = Field(..., description="Transit year (e.g., '2024')"),
    transit_hour: str = Field(..., description="Transit hour in 24h format (e.g., '18')"),
    transit_min: str = Field(..., description="Transit minute (e.g., '10')"),
    transit_sec: str = Field(..., description="Transit second (e.g., '05')"),
) -> str:
    """Get basic transit overview for the natal chart at a specific moment.

    Returns the planetary transits at the given transit date/time and their
    aspects to natal planets. Transits show how the sky at that moment
    activates the birth chart, indicating periods of opportunity, challenge,
    and transformation in various life areas.
    """
    api_key, auth_token = _get_credentials(ctx)
    payload = _natal_payload(params)
    payload.update({
        "transit_day": transit_day,
        "transit_month": transit_month,
        "transit_year": transit_year,
        "transit_hour": transit_hour,
        "transit_min": transit_min,
        "transit_sec": transit_sec,
    })
    return await _call_divine_api("/western-api/v1/transit/basic", payload, API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_transit_daily", annotations=TOOL_ANNOTATIONS)
async def divine_western_transit_daily(params: WesternNatalInput, ctx: Context) -> str:
    """Get daily transit report for the natal chart.

    Returns today's transits affecting the birth chart with interpretations.
    For a broader view, also call divine_western_transit_weekly and
    divine_western_transit_monthly in parallel.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/transit/daily", _natal_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_transit_weekly", annotations=TOOL_ANNOTATIONS)
async def divine_western_transit_weekly(
    params: WesternNatalInput,
    ctx: Context,
    transit_planet: str = Field(..., description="Transiting planet to track for the week (e.g., 'moon', 'mercury', 'venus', 'mars')"),
) -> str:
    """Get weekly transit report for the natal chart.

    Returns this week's transits of the chosen transit_planet affecting the
    birth chart, with aspect timings. Covers the planet's movements and
    aspects forming during the week, highlighting key days for action,
    reflection, or caution.
    """
    api_key, auth_token = _get_credentials(ctx)
    payload = _natal_payload(params)
    payload["transit_planet"] = transit_planet
    return await _call_divine_api("/western-api/v1/transit/weekly", payload, API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_transit_monthly", annotations=TOOL_ANNOTATIONS)
async def divine_western_transit_monthly(
    params: WesternNatalInput,
    ctx: Context,
    transit_planet: str = Field(..., description="Transiting planet to track for the month (e.g., 'moon', 'mercury', 'venus', 'mars')"),
    transit_month: str = Field(..., description="Transit month (e.g., '10')"),
    transit_year: str = Field(..., description="Transit year (e.g., '2025')"),
    transit_lat: str = Field(..., description="Latitude of the transit location (e.g., '28.6139')"),
    transit_lon: str = Field(..., description="Longitude of the transit location (e.g., '77.2090')"),
    transit_tzone: str = Field(..., description="Timezone offset of the transit location (e.g., '5.5')"),
    transit_place: str = Field(..., description="Transit place name (e.g., 'New Delhi')"),
    aspects_type: str | None = Field(default=None, description="Optional aspect filter (e.g., 'ALL')"),
    aspect_orbs_type: str | None = Field(default=None, description="Optional aspect orb type (e.g., 'FIXED')"),
    aspect_orbs_value: str | None = Field(default=None, description="Optional aspect orb value (e.g., '5_30')"),
) -> str:
    """Get monthly transit report for the natal chart.

    Returns the chosen transit_planet's transits over the given month
    affecting the birth chart, with aspect start/peak/end timings.
    Covers the planet's movements and aspects that shape the month's themes.
    """
    api_key, auth_token = _get_credentials(ctx)
    payload = _natal_payload(params)
    payload.update({
        "transit_planet": transit_planet,
        "transit_month": transit_month,
        "transit_year": transit_year,
        "transit_lat": transit_lat,
        "transit_lon": transit_lon,
        "transit_tzone": transit_tzone,
        "transit_place": transit_place,
    })
    if aspects_type is not None:
        payload["aspects_type"] = aspects_type
    if aspect_orbs_type is not None:
        payload["aspect_orbs_type"] = aspect_orbs_type
    if aspect_orbs_value is not None:
        payload["aspect_orbs_value"] = aspect_orbs_value
    return await _call_divine_api("/western-api/v2/transit/monthly", payload, API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_transit_house", annotations=TOOL_ANNOTATIONS)
async def divine_western_transit_house(params: WesternFullTransitInput, ctx: Context) -> str:
    """Get transit house overlay report for the natal chart.

    Returns which natal houses the transiting planets are moving through at
    the given transit date/time and location, indicating which life areas
    are being activated and energized by cosmic influences.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/transit/house", _full_transit_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_full_transit", annotations=TOOL_ANNOTATIONS)
async def divine_western_full_transit(
    params: WesternFullTransitInput,
    ctx: Context,
    transit_planet: str = Field(..., description="Transiting planet to analyze (e.g., 'moon', 'mercury', 'venus', 'mars')"),
    aspects_type: str | None = Field(default=None, description="Optional aspect filter (e.g., 'ALL')"),
    aspect_orbs_type: str | None = Field(default=None, description="Optional aspect orb type (e.g., 'FIXED')"),
    aspect_orbs_value: str | None = Field(default=None, description="Optional aspect orb value (e.g., '5_30')"),
) -> str:
    """Get a comprehensive full transit report for the natal chart.

    Returns a complete transit analysis for the chosen transit_planet at the
    given transit date and location: aspects to natal planets with
    start/peak/end times and detailed interpretations. This is the most
    thorough single-planet transit report available.
    """
    api_key, auth_token = _get_credentials(ctx)
    payload = _full_transit_payload(params)
    payload["transit_planet"] = transit_planet
    if aspects_type is not None:
        payload["aspects_type"] = aspects_type
    if aspect_orbs_type is not None:
        payload["aspect_orbs_type"] = aspect_orbs_type
    if aspect_orbs_value is not None:
        payload["aspect_orbs_value"] = aspect_orbs_value
    return await _call_divine_api("/western-api/v1/full-transit", payload, API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_planet_retrograde_transit", annotations=TOOL_ANNOTATIONS)
async def divine_western_planet_retrograde_transit(params: WesternTransitPlanetInput, ctx: Context) -> str:
    """Get retrograde transit information for a specific planet.

    Returns retrograde periods for the specified planet during the given
    month and year. Retrograde periods are when a planet appears to move
    backward, traditionally associated with delays, review, and
    internalization of that planet's themes.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/planet-retrograde-transit", _transit_planet_payload(params), API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_planet_combustion_transit", annotations=TOOL_ANNOTATIONS)
async def divine_western_planet_combustion_transit(params: WesternTransitPlanetInput, ctx: Context) -> str:
    """Get combustion transit information for a specific planet.

    Returns combustion periods for the specified planet during the given
    month and year. Combustion occurs when a planet is too close to the Sun,
    becoming weakened or hidden. This affects the planet's ability to express
    its significations clearly.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/planet-combustion-transit", _transit_planet_payload(params), API_HOST_8, api_key=api_key, auth_token=auth_token)


# ══════════════════════════════════════════════


@mcp.tool(name="divine_western_transit_wheel_chart", annotations=TOOL_ANNOTATIONS)
async def divine_western_transit_wheel_chart(params: WesternFullTransitInput, ctx: Context) -> str:
    """Generate a transit wheel chart overlaying current transits on the natal chart.

    Returns a visual wheel chart showing natal planet positions in the inner
    ring and current transit positions in the outer ring.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/transit/wheel-chart", _full_transit_payload(params), API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_transit_planetary_positions", annotations=TOOL_ANNOTATIONS)
async def divine_western_transit_planetary_positions(params: WesternFullTransitInput, ctx: Context) -> str:
    """Get planetary positions for both natal and transit charts.

    Returns detailed planetary positions for both the birth chart and the
    transit date, showing sign, degree, house placement, and aspects.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/transit/planetary-positions", _full_transit_payload(params), API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_planetary_ingress", annotations=TOOL_ANNOTATIONS)
async def divine_western_planetary_ingress(params: WesternTransitPlanetInput, ctx: Context) -> str:
    """Get planetary ingress data for a specific planet.

    Returns sign ingress dates for the specified planet during the given
    month and year. An ingress occurs when a planet moves from one zodiac
    sign to the next, marking significant shifts in energy and themes.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/planetary-ingress", _transit_planet_payload(params), API_HOST_8, api_key=api_key, auth_token=auth_token)


# ══════════════════════════════════════════════
# COMPOSITE TOOLS (4) - astroapi-8.divineapi.com
# ══════════════════════════════════════════════


@mcp.tool(name="divine_western_composite_planetary_positions", annotations=TOOL_ANNOTATIONS)
async def divine_western_composite_planetary_positions(params: WesternSynastryInput, ctx: Context) -> str:
    """Get planetary positions for the composite chart of two persons.

    The composite chart is created by calculating the midpoints of each
    pair of planets (e.g., midpoint of both Suns, midpoint of both Moons).
    It represents the relationship itself as an entity, revealing the
    purpose, dynamics, and potential of the partnership.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/composite/planetary-positions", _synastry_payload(params), API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_composite_house_cusps", annotations=TOOL_ANNOTATIONS)
async def divine_western_composite_house_cusps(params: WesternSynastryInput, ctx: Context) -> str:
    """Get house cusps for the composite chart of two persons.

    Returns the house cusps of the composite (midpoint) chart, showing
    which life areas the relationship emphasizes. For example, a strong
    composite 7th house indicates a partnership-focused relationship,
    while a strong 10th house suggests a public or career-oriented union.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/composite/house-cusps", _synastry_payload(params), API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_composite_aspect_table", annotations=TOOL_ANNOTATIONS)
async def divine_western_composite_aspect_table(params: WesternSynastryInput, ctx: Context) -> str:
    """Get the aspect table for the composite chart of two persons.

    Returns all aspects between planets in the composite chart. These
    aspects describe the internal dynamics of the relationship, showing
    where the partnership flows easily (trines, sextiles) and where it
    faces structural challenges (squares, oppositions).
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/composite/aspect-table", _synastry_payload(params), API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_composite_natal_wheel_chart", annotations=TOOL_ANNOTATIONS)
async def divine_western_composite_natal_wheel_chart(params: WesternSynastryInput, ctx: Context) -> str:
    """Generate a visual composite chart wheel image for two persons.

    Returns an image URL of the composite (midpoint) chart wheel showing
    the relationship's planetary placements, house cusps, and zodiac signs
    in a traditional circular format.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/composite/natal-wheel-chart", _synastry_payload(params), API_HOST_8, api_key=api_key, auth_token=auth_token)


# ══════════════════════════════════════════════
# ADVANCED NATAL TOOLS (11) -astroapi-8.divineapi.com
# ══════════════════════════════════════════════


@mcp.tool(name="divine_western_arabic_lots", annotations=TOOL_ANNOTATIONS)
async def divine_western_arabic_lots(params: WesternNatalInput, ctx: Context) -> str:
    """Get Arabic Lots (Parts) for the natal chart.

    Returns calculated Arabic Lots including the Part of Fortune, Part of
    Spirit, Part of Eros, Part of Marriage, and others. Arabic Lots are
    sensitive points derived from three chart factors (usually Ascendant,
    planet, and another planet), each revealing a specific life theme.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/arabic-lots", _natal_payload(params), API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_asteroid_positions", annotations=TOOL_ANNOTATIONS)
async def divine_western_asteroid_positions(params: WesternNatalInput, ctx: Context) -> str:
    """Get asteroid positions in the natal chart.

    Returns positions of major asteroids including Chiron (the Wounded Healer),
    Ceres (nurturing), Pallas Athena (wisdom and strategy), Juno (partnership
    and commitment), and Vesta (devotion and sacred focus). Asteroids add
    nuance and depth to chart interpretation.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/asteroid-positions", _natal_payload(params), API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_fixed_stars_list", annotations=TOOL_ANNOTATIONS)
async def divine_western_fixed_stars_list(ctx: Context, params: WesternFixedStarsListInput | None = None) -> str:
    """Get the catalog of fixed star names supported by the API.

    Returns the full list of fixed star identifiers (e.g. 'Abhijit',
    'Acrux', 'Aldebaran') that can be passed to
    divine_western_fixed_stars_details via its star_list parameter.
    This endpoint needs no input; any provided fields are ignored.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/fixed-stars-list", {}, API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_fixed_stars_details", annotations=TOOL_ANNOTATIONS)
async def divine_western_fixed_stars_details(
    params: WesternNatalInput,
    ctx: Context,
    star_list: str = Field(..., description="Comma-separated fixed star names to analyze (e.g., 'Abhijit,Aboras,A3558'). Get valid names from divine_western_fixed_stars_list."),
) -> str:
    """Get detailed positions and placements for specific fixed stars.

    Returns each requested star's zodiac position, house placement, and
    motion relative to the natal chart. Pass the stars to analyze in
    star_list; valid star names come from divine_western_fixed_stars_list.
    """
    api_key, auth_token = _get_credentials(ctx)
    payload = _natal_payload(params)
    payload["star_list"] = star_list
    return await _call_divine_api("/western-api/v1/fixed-stars-details", payload, API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_planetary_midpoints", annotations=TOOL_ANNOTATIONS)
async def divine_western_planetary_midpoints(params: WesternNatalInput, ctx: Context) -> str:
    """Get planetary midpoints for the natal chart.

    Returns all significant midpoints between natal planets. Midpoints are
    the halfway points between two planets, representing a blending of their
    energies. When activated by transits or other planets, midpoints can
    trigger important events. Central to the Uranian/Hamburg school of astrology.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/planetary-midpoints", _natal_payload(params), API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_eclipse", annotations=TOOL_ANNOTATIONS)
async def divine_western_eclipse(params: WesternNatalInput, ctx: Context) -> str:
    """Get eclipse information relative to the natal chart.

    Returns solar and lunar eclipses and their relationship to natal planets
    and points. Eclipses are powerful lunations that can trigger major life
    events, especially when they conjoin natal planets or angles. Their
    effects can unfold over months.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/eclipse", _natal_payload(params), API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_declinations_parallels", annotations=TOOL_ANNOTATIONS)
async def divine_western_declinations_parallels(params: WesternNatalInput, ctx: Context) -> str:
    """Get declinations and parallels for the natal chart.

    Returns planetary declinations (distance north or south of the celestial
    equator) and parallel/contraparallel aspects. Parallels act like
    conjunctions and contraparallels like oppositions, adding a hidden layer
    of planetary connections not visible in standard longitude-based charts.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/declinations-parallels", _natal_payload(params), API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_aspect_patterns", annotations=TOOL_ANNOTATIONS)
async def divine_western_aspect_patterns(params: WesternNatalInput, ctx: Context) -> str:
    """Get aspect patterns in the natal chart.

    Returns identified aspect patterns such as Grand Trines, T-Squares,
    Grand Crosses, Yods (Finger of God), Kites, Mystic Rectangles, and
    Stelliums. These multi-planet configurations reveal core life themes,
    talents, and challenges that dominate the native's experience.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/aspect-patterns", _natal_payload(params), API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_chart_shape", annotations=TOOL_ANNOTATIONS)
async def divine_western_chart_shape(params: WesternNatalInput, ctx: Context) -> str:
    """Get the overall chart shape/pattern for the natal chart.

    Returns the chart shape classification (Bundle, Bowl, Bucket, Locomotive,
    Seesaw, Splash, Splay) based on planetary distribution. The chart shape
    provides immediate insight into the native's approach to life, energy
    distribution, and focus areas.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/chart-shape", _natal_payload(params), API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_other_minor_bodies", annotations=TOOL_ANNOTATIONS)
async def divine_western_other_minor_bodies(params: WesternNatalInput, ctx: Context) -> str:
    """Get positions of other minor celestial bodies in the natal chart.

    Returns positions of additional minor bodies such as Lilith (Black Moon),
    the Lunar Nodes (North and South Node), Part of Fortune, Vertex, and
    other sensitive points that add depth to natal chart analysis.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/western-api/v1/other-minor-bodies", _natal_payload(params), API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_dominants", annotations=TOOL_ANNOTATIONS)
async def divine_western_dominants(
    params: WesternNatalInput,
    ctx: Context,
    method: str = Field(..., description="Calculation method: 'TRADITIONAL' or 'MODERN'. The two methods weight planets differently and produce different rankings."),
) -> str:
    """Get dominant planets, signs, and elements in the natal chart.

    Returns analysis of which planets, signs, elements (Fire, Earth, Air,
    Water), and modalities (Cardinal, Fixed, Mutable) dominate the chart,
    using the chosen calculation method (TRADITIONAL or MODERN).
    Dominance analysis reveals the native's core temperament, preferred
    mode of expression, and psychological orientation.
    """
    api_key, auth_token = _get_credentials(ctx)
    payload = _natal_payload(params)
    err = _apply_dominants_method(payload, method)
    if err:
        return err
    return await _call_divine_api("/western-api/v1/dominants", payload, API_HOST_8, api_key=api_key, auth_token=auth_token)


# ══════════════════════════════════════════════
# PROGRESSIONS & RETURNS TOOLS (5) -astroapi-8.divineapi.com
# ══════════════════════════════════════════════


@mcp.tool(name="divine_western_planet_returns_list", annotations=TOOL_ANNOTATIONS)
async def divine_western_planet_returns_list(
    params: WesternNatalInput,
    ctx: Context,
    planet: str = Field(..., description="Planet whose returns to list (e.g., 'moon', 'sun', 'mercury', 'venus', 'mars')"),
    return_year: str = Field(..., description="Year to list returns for (e.g., '2024')"),
    return_lat: str = Field(..., description="Latitude of the return location (e.g., '19.0760')"),
    return_lon: str = Field(..., description="Longitude of the return location (e.g., '72.8774')"),
    return_tzone: str = Field(..., description="Timezone offset of the return location (e.g., '5.5')"),
    return_place: str = Field(..., description="Return place name (e.g., 'Mumbai, Maharashtra, India')"),
) -> str:
    """Get a list of planetary returns for the natal chart.

    Returns the dates in return_year when the chosen planet returns to its
    natal position at the given return location, each with a return_key for
    use with divine_western_planet_return_details. The most well-known is
    the Solar Return (birthday chart), but lunar returns (monthly), Mercury
    returns, Venus returns, Mars returns, Jupiter returns (every 12 years),
    and Saturn returns (every 29 years) are all significant timing techniques.
    """
    api_key, auth_token = _get_credentials(ctx)
    payload = _natal_payload(params)
    payload.update({
        "planet": planet,
        "return_year": return_year,
        "return_lat": return_lat,
        "return_lon": return_lon,
        "return_tzone": return_tzone,
        "return_place": return_place,
    })
    return await _call_divine_api("/western-api/v1/planet-returns-list", payload, API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_planet_return_details", annotations=TOOL_ANNOTATIONS)
async def divine_western_planet_return_details(
    params: WesternNatalInput,
    ctx: Context,
    planet: str = Field(..., description="Planet whose return chart to compute (e.g., 'moon', 'sun', 'mercury')"),
    return_key: str = Field(..., description="Return identifier from divine_western_planet_returns_list (e.g., 'MOON_P_1705862940000')"),
    return_year: str = Field(..., description="Year of the return (e.g., '2024')"),
    return_lat: str = Field(..., description="Latitude of the return location (e.g., '19.0760')"),
    return_lon: str = Field(..., description="Longitude of the return location (e.g., '72.8774')"),
    return_tzone: str = Field(..., description="Timezone offset of the return location (e.g., '5.5')"),
    return_place: str = Field(..., description="Return place name (e.g., 'Mumbai, Maharashtra, India')"),
) -> str:
    """Get detailed planetary return chart information.

    Returns the full chart details for the planetary return identified by
    return_key (from divine_western_planet_returns_list), including planet
    positions, house cusps, and aspects at the exact moment the transiting
    planet returns to its natal degree. The return chart is used to forecast
    themes for the upcoming cycle.
    """
    api_key, auth_token = _get_credentials(ctx)
    payload = _natal_payload(params)
    payload.update({
        "planet": planet,
        "return_key": return_key,
        "return_year": return_year,
        "return_lat": return_lat,
        "return_lon": return_lon,
        "return_tzone": return_tzone,
        "return_place": return_place,
    })
    return await _call_divine_api("/western-api/v1/planet-return-details", payload, API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_progressed_lunar_events", annotations=TOOL_ANNOTATIONS)
async def divine_western_progressed_lunar_events(
    params: WesternNatalInput,
    ctx: Context,
    prenatal_type: str = Field(..., description="Prenatal event type (e.g., 'SYZYGY' for the last New/Full Moon before birth)"),
) -> str:
    """Get progressed lunar events for the natal chart.

    Returns secondary progressed Moon phases, sign ingresses, and aspects
    anchored to the chosen prenatal_type. The progressed Moon moves about
    one degree per month (one sign every 2.5 years), marking major
    emotional and developmental shifts. Progressed New Moons and Full Moons
    indicate pivotal life chapters.
    """
    api_key, auth_token = _get_credentials(ctx)
    payload = _natal_payload(params)
    payload["prenatal_type"] = prenatal_type
    return await _call_divine_api("/western-api/v1/progressed-lunar-events", payload, API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_planetary_arc_directions", annotations=TOOL_ANNOTATIONS)
async def divine_western_planetary_arc_directions(
    params: WesternNatalInput,
    ctx: Context,
    planet: str = Field(..., description="Planet whose arc directs the chart (e.g., 'Venus'; 'Sun' gives classic solar arc)"),
    progressed_day: str = Field(..., description="Target date day for the direction (e.g., '13')"),
    progressed_month: str = Field(..., description="Target date month for the direction (e.g., '06')"),
    progressed_year: str = Field(..., description="Target date year for the direction (e.g., '2021')"),
) -> str:
    """Get planetary arc directions for the natal chart.

    Returns arc directions for the chosen planet to the given target date,
    a predictive technique where all natal planets are advanced by the
    planet's progressed distance. When directed planets aspect natal
    positions, they indicate significant life events and turning points.
    """
    api_key, auth_token = _get_credentials(ctx)
    payload = _natal_payload(params)
    payload.update({
        "planet": planet,
        "progressed_day": progressed_day,
        "progressed_month": progressed_month,
        "progressed_year": progressed_year,
    })
    return await _call_divine_api("/western-api/v1/planetary-arc-directions", payload, API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_secondary_progressions", annotations=TOOL_ANNOTATIONS)
async def divine_western_secondary_progressions(
    params: WesternNatalInput,
    ctx: Context,
    progressed_day: str = Field(..., description="Target date day for the progression (e.g., '13')"),
    progressed_month: str = Field(..., description="Target date month for the progression (e.g., '06')"),
    progressed_year: str = Field(..., description="Target date year for the progression (e.g., '2021')"),
    progressed_hour: str = Field(..., description="Target time hour in 24h format (e.g., '12')"),
    progressed_min: str = Field(..., description="Target time minute (e.g., '50')"),
    progressed_sec: str = Field(..., description="Target time second (e.g., '20')"),
    progressed_type: str = Field(..., description="Progression rate method (e.g., 'ARMC1_NAIBOD')"),
    planet: str | None = Field(default=None, description="Optional planet to focus the progression on (e.g., 'Venus')"),
) -> str:
    """Get secondary progressions for the natal chart.

    Returns the secondary progressed chart for the given target date/time,
    where each day after birth equals one year of life, using the chosen
    progressed_type rate method. Secondary progressions reveal the inner
    psychological evolution of the native, showing gradual shifts in
    identity, emotional needs, and life direction over time.
    """
    api_key, auth_token = _get_credentials(ctx)
    payload = _natal_payload(params)
    payload.update({
        "progressed_day": progressed_day,
        "progressed_month": progressed_month,
        "progressed_year": progressed_year,
        "progressed_hour": progressed_hour,
        "progressed_min": progressed_min,
        "progressed_sec": progressed_sec,
        "progressed_type": progressed_type,
    })
    if planet is not None:
        payload["planet"] = planet
    return await _call_divine_api("/western-api/v1/secondary-progressions", payload, API_HOST_8, api_key=api_key, auth_token=auth_token)


# ══════════════════════════════════════════════
# PRENATAL TOOLS (2) -astroapi-8.divineapi.com
# ══════════════════════════════════════════════


@mcp.tool(name="divine_western_prenatal_list", annotations=TOOL_ANNOTATIONS)
async def divine_western_prenatal_list(
    params: WesternNatalInput,
    ctx: Context,
    prenatal_type: str = Field(..., description="Prenatal event type (e.g., 'SYZYGY' for the last New/Full Moon before birth)"),
) -> str:
    """Get a list of prenatal eclipses and lunations for the natal chart.

    Returns the prenatal events of the chosen prenatal_type before birth,
    each with a prenatal_key for use with divine_western_prenatal_details.
    These prenatal celestial events are believed to set the karmic backdrop
    and soul-level intentions for the incarnation.
    """
    api_key, auth_token = _get_credentials(ctx)
    payload = _natal_payload(params)
    payload["prenatal_type"] = prenatal_type
    return await _call_divine_api("/western-api/v1/prenatal-list", payload, API_HOST_8, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_western_prenatal_details", annotations=TOOL_ANNOTATIONS)
async def divine_western_prenatal_details(
    params: WesternNatalInput,
    ctx: Context,
    prenatal_key: str = Field(..., description="Prenatal event identifier from divine_western_prenatal_list (e.g., 'SYZYGY_NM_P_648635040000')"),
) -> str:
    """Get detailed prenatal eclipse and lunation analysis for the natal chart.

    Returns detailed chart data for the prenatal event identified by
    prenatal_key (from divine_western_prenatal_list), including planetary
    positions, sign, degree, and aspects to natal planets. The prenatal
    eclipse degree is considered a sensitive point in the chart that
    remains active throughout life.
    """
    api_key, auth_token = _get_credentials(ctx)
    payload = _natal_payload(params)
    payload["prenatal_key"] = prenatal_key
    return await _call_divine_api("/western-api/v1/prenatal-details", payload, API_HOST_8, api_key=api_key, auth_token=auth_token)


# ──────────────────────────────────────────────
# OAuth Login Form -/divine-login
# ──────────────────────────────────────────────

_LOGIN_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>Divine API - Connect Your Account</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
               min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .card { background: #fff; border-radius: 16px; padding: 40px; max-width: 420px; width: 90%;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3); }
        .logo { text-align: center; margin-bottom: 24px; font-size: 28px; }
        h1 { font-size: 22px; color: #1a1a2e; margin-bottom: 8px; text-align: center; }
        p { color: #666; font-size: 14px; margin-bottom: 24px; text-align: center; }
        label { display: block; font-size: 13px; font-weight: 600; color: #333; margin-bottom: 6px; }
        input { width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 8px;
                font-size: 14px; margin-bottom: 16px; transition: border-color 0.2s; }
        input:focus { outline: none; border-color: #0f3460; }
        button { width: 100%; padding: 14px; background: #0f3460; color: #fff; border: none;
                 border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer;
                 transition: background 0.2s; }
        button:hover { background: #1a1a2e; }
        .help { text-align: center; margin-top: 16px; font-size: 12px; color: #999; }
        .help a { color: #0f3460; }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">&#128302;</div>
        <h1>Connect Divine API</h1>
        <p>Enter your Divine API credentials to connect Divine API tools to Claude.</p>
        <form method="POST" action="/divine-login/submit">
            <input type="hidden" name="pending" value="{pending_id}">
            <label>API Key</label>
            <input type="text" name="api_key" placeholder="Your Divine API Key" required>
            <label>Auth Token</label>
            <input type="password" name="auth_token" placeholder="Your Divine Auth Token" required>
            <button type="submit">Connect</button>
        </form>
        <p class="help">Get your credentials at <a href="https://divineapi.com/api-keys" target="_blank">divineapi.com/api-keys</a></p>
    </div>
<script>
});
</script>
</body>
</html>"""


if _TRANSPORT == "http":
    @mcp.custom_route("/divine-login", methods=["GET"])
    async def divine_login_form(request):
        from starlette.responses import HTMLResponse
        pending_id = request.query_params.get("pending", "")
        html = _LOGIN_HTML.replace("{pending_id}", pending_id)
        return HTMLResponse(html)

    @mcp.custom_route("/divine-login/submit", methods=["POST"])
    async def divine_login_submit(request):
        from starlette.responses import RedirectResponse
        form = await request.form()
        pending_id = form.get("pending", "")
        api_key = form.get("api_key", "")
        auth_token = form.get("auth_token", "")

        if not _auth_provider or not hasattr(_auth_provider, "_pending_auths"):
            from starlette.responses import HTMLResponse
            return HTMLResponse("Error: Invalid session", status_code=400)

        pending = _auth_provider._pending_auths.pop(pending_id, None)
        if not pending:
            from starlette.responses import HTMLResponse
            return HTMLResponse("Error: Session expired. Please try connecting again.", status_code=400)

        # Create auth code with Divine API credentials embedded
        code = secrets.token_urlsafe(32)
        _auth_provider._auth_codes[code] = {
            "client_id": pending["client_id"],
            "divine_api_key": api_key,
            "divine_auth_token": auth_token,
            "code_challenge": pending["code_challenge"],
            "redirect_uri": pending["redirect_uri"],
            "redirect_uri_provided_explicitly": pending["redirect_uri_provided_explicitly"],
            "scopes": pending["scopes"],
            "expires_at": time.time() + 300,
        }

        # Redirect back to Claude with the auth code
        redirect_url = construct_redirect_uri(
            pending["redirect_uri"],
            code=code,
            state=pending.get("state"),
        )
        return RedirectResponse(url=redirect_url, status_code=302)


# ──────────────────────────────────────────────
# HTTP / ASGI App
# ──────────────────────────────────────────────




class ApiKeyToJwtMiddleware:
    """ASGI middleware that converts direct DivineAPI credentials into the JWT
    Bearer token the MCP auth layer expects. Two client shapes are supported:

    1. X-Divine-Api-Key + X-Divine-Auth-Token headers (VS Code, OpenAI, Gemini,
       custom clients).
    2. Authorization: Bearer <api_key>:<auth_token> - a single-field credential
       combo for platforms that cannot send custom headers (e.g. the Claude
       Messages API MCP connector). A real OAuth-issued JWT never contains a
       colon, so valid tokens are never touched.
    """

    def __init__(self, app, jwt_secret):
        self.app = app
        self.jwt_secret = jwt_secret

    def _mint(self, api_key, auth_token):
        return jwt.encode(
            {
                "divine_api_key": api_key,
                "divine_auth_token": auth_token,
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
            },
            self.jwt_secret,
            algorithm="HS256",
        )

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers_list = scope.get("headers", [])
            headers_dict = {k: v for k, v in headers_list}
            api_key = headers_dict.get(b"x-divine-api-key", b"").decode()
            auth_token = headers_dict.get(b"x-divine-auth-token", b"").decode()
            bearer = ""
            for k, v in headers_list:
                if k == b"authorization" and v.startswith(b"Bearer "):
                    bearer = v[7:].decode()
                    break

            token = None
            if api_key and auth_token and not bearer:
                token = self._mint(api_key, auth_token)
            elif ":" in bearer:
                combo_key, _, combo_token = bearer.partition(":")
                if combo_key and combo_token:
                    token = self._mint(combo_key.strip(), combo_token.strip())

            if token:
                new_headers = [(k, v) for k, v in headers_list if k != b"authorization"]
                new_headers.append((b"authorization", f"Bearer {token}".encode()))
                scope = dict(scope, headers=new_headers)

        await self.app(scope, receive, send)


def create_http_app():
    """Create ASGI app for production HTTP deployment with uvicorn."""
    from starlette.middleware.cors import CORSMiddleware

    app = mcp.streamable_http_app()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=[
            "mcp-protocol-version",
            "mcp-session-id",
            "Authorization",
            "Content-Type",
            "X-Divine-Api-Key",
            "X-Divine-Auth-Token",
        ],
        expose_headers=["mcp-session-id"],
    )
    return ApiKeyToJwtMiddleware(app, _JWT_SECRET)


# Module-level ASGI app for uvicorn (only created in HTTP mode)
app = create_http_app() if _TRANSPORT == "http" else None


# ──────────────────────────────────────────────
# Server Entry Point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    if _TRANSPORT == "http":
        mcp.run(transport="streamable-http", host="0.0.0.0", port=8000)
    else:
        mcp.run(transport="stdio")
