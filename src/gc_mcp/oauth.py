"""OAuth 2.1 + DCR + Google OAuth Proxy + Desktop-Commander PKCE Device Flow."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _pkce_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return _b64url(digest)


class OAuthManager:
    """Handles MCP OAuth 2.1 (DCR + PKCE), Google OIDC upstream, and Device Code + PKCE flow."""

    def __init__(
        self,
        base_url: str | None = None,
        auth_mode: str | None = None,
        google_client_id: str | None = None,
        google_client_secret: str | None = None,
        allowed_emails: list[str] | None = None,
        signing_secret: str | None = None,
        static_tokens: list[str] | None = None,
    ) -> None:
        self.base_url = (
            base_url or os.environ.get("GC_MCP_BASE_URL", "https://bhd-main2.raven-tuatara.ts.net:18375")
        ).rstrip("/")
        self.auth_mode = (auth_mode or os.environ.get("GC_MCP_AUTH_MODE", "optional")).lower()
        self.google_client_id = google_client_id or os.environ.get("GOOGLE_CLIENT_ID", "")
        self.google_client_secret = google_client_secret or os.environ.get("GOOGLE_CLIENT_SECRET", "")
        raw_emails = os.environ.get("GC_OAUTH_ALLOWED_EMAILS", "buihongduc132@gmail.com")
        self.allowed_emails = set(
            allowed_emails if allowed_emails is not None else [e.strip() for e in raw_emails.split(",") if e.strip()]
        )
        self.signing_secret = (
            signing_secret or os.environ.get("GC_OAUTH_SIGNING_SECRET") or secrets.token_hex(32)
        ).encode("utf-8")
        env_tok = os.environ.get("GC_MCP_API_TOKEN", "")
        self.static_tokens = set(static_tokens or ([env_tok] if env_tok else []))
        self.clients: dict[str, dict[str, Any]] = {}
        self.auth_codes: dict[str, dict[str, Any]] = {}
        self.device_codes: dict[str, dict[str, Any]] = {}
        self.refresh_tokens: dict[str, dict[str, Any]] = {}

    def metadata(self) -> dict[str, Any]:
        return {
            "issuer": self.base_url,
            "authorization_endpoint": f"{self.base_url}/oauth/authorize",
            "token_endpoint": f"{self.base_url}/oauth/token",
            "registration_endpoint": f"{self.base_url}/oauth/register",
            "device_authorization_endpoint": f"{self.base_url}/device/code",
            "device_poll_endpoint": f"{self.base_url}/device/poll",
            "scopes_supported": ["openid", "email", "profile", "mcp:tools", "gc:admin"],
            "response_types_supported": ["code"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["S256"],
            "google_oauth_configured": bool(self.google_client_id),
            "auth_mode": self.auth_mode,
        }

    def protected_resource_metadata(self) -> dict[str, Any]:
        return {
            "resource": f"{self.base_url}/mcp",
            "authorization_servers": [self.base_url],
            "scopes_supported": ["openid", "email", "profile", "mcp:tools", "gc:admin"],
            "bearer_methods_supported": ["header"],
        }

    def register_client(self, body: dict[str, Any]) -> dict[str, Any]:
        client_id = f"mcp_{secrets.token_urlsafe(12)}"
        client_secret = secrets.token_urlsafe(24)
        record = {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_name": body.get("client_name", "MCP Client"),
            "redirect_uris": body.get("redirect_uris", ["http://localhost:8000/callback"]),
            "grant_types": body.get("grant_types", ["authorization_code", "refresh_token"]),
            "response_types": body.get("response_types", ["code"]),
            "token_endpoint_auth_method": body.get("token_endpoint_auth_method", "none"),
            "client_id_issued_at": int(time.time()),
        }
        self.clients[client_id] = record
        return record

    def issue_token(self, sub: str, email: str, scope: str = "openid email mcp:tools", ttl: int = 3600) -> dict[str, Any]:
        now = int(time.time())
        claims = {
            "iss": self.base_url,
            "sub": sub,
            "email": email,
            "scope": scope,
            "iat": now,
            "exp": now + ttl,
        }
        payload_b64 = _b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
        sig = _b64url(hmac.new(self.signing_secret, payload_b64.encode("ascii"), hashlib.sha256).digest())
        access_token = f"gcmcp.{payload_b64}.{sig}"
        refresh_token = f"gcref_{secrets.token_urlsafe(24)}"
        self.refresh_tokens[refresh_token] = {"sub": sub, "email": email, "scope": scope}
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ttl,
            "refresh_token": refresh_token,
            "scope": scope,
        }

    def verify_token(self, token: str) -> dict[str, Any] | None:
        if not token:
            return None
        if token in self.static_tokens:
            return {"sub": "static-token", "email": "operator@local", "scope": "mcp:tools gc:admin"}
        if token.startswith("gcmcp."):
            parts = token.split(".")
            if len(parts) != 3:
                return None
            _, payload_b64, sig = parts
            expected = _b64url(
                hmac.new(self.signing_secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
            )
            if not hmac.compare_digest(sig, expected):
                return None
            padded = payload_b64 + "=" * (-len(payload_b64) % 4)
            try:
                claims = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
            except Exception:
                return None
            if int(claims.get("exp", 0)) < int(time.time()):
                return None
            email = claims.get("email", "")
            if self.allowed_emails and email and email not in self.allowed_emails and email != "operator@local":
                return None
            return claims
        return None

    def check_request_auth(self, auth_header: str | None) -> tuple[bool, dict[str, Any] | None]:
        token = ""
        if auth_header and auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
        claims = self.verify_token(token) if token else None
        if claims is not None:
            return True, claims
        if self.auth_mode != "required":
            return True, {"sub": "tailnet-anonymous", "mode": self.auth_mode}
        return False, None

    def create_authorization_code(
        self,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str = "S256",
        state: str = "",
        email: str = "buihongduc132@gmail.com",
        scope: str = "openid email mcp:tools",
    ) -> str:
        code = f"gccode_{secrets.token_urlsafe(20)}"
        self.auth_codes[code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "state": state,
            "email": email,
            "scope": scope,
            "expires_at": time.time() + 600,
        }
        return code

    def exchange_code(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        grant_type = body.get("grant_type", "authorization_code")
        if grant_type == "refresh_token":
            rt = body.get("refresh_token", "")
            info = self.refresh_tokens.get(rt)
            if not info:
                return 400, {"error": "invalid_grant", "error_description": "Invalid refresh_token"}
            return 200, self.issue_token(sub=info["sub"], email=info["email"], scope=info["scope"])

        code = body.get("code", "")
        verifier = body.get("code_verifier", "")
        info = self.auth_codes.pop(code, None)
        if not info or info["expires_at"] < time.time():
            return 400, {"error": "invalid_grant", "error_description": "Invalid or expired authorization code"}
        if info.get("code_challenge"):
            if not verifier or _pkce_s256(verifier) != info["code_challenge"]:
                return 400, {"error": "invalid_grant", "error_description": "PKCE code_verifier mismatch"}
        email = info["email"]
        if self.allowed_emails and email not in self.allowed_emails:
            return 403, {"error": "access_denied", "error_description": f"Email {email} not in allowlist"}
        return 200, self.issue_token(sub=f"google:{email}", email=email, scope=info["scope"])

    def start_device_flow(self, body: dict[str, Any]) -> dict[str, Any]:
        device_code = f"dc_{secrets.token_urlsafe(24)}"
        user_code = f"{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"
        device_id = body.get("device_id") or f"dev_{secrets.token_hex(6)}"
        code_challenge = body.get("code_challenge", "")
        code_challenge_method = body.get("code_challenge_method", "S256")
        expires_in = 600
        self.device_codes[device_code] = {
            "device_code": device_code,
            "user_code": user_code,
            "device_id": device_id,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "status": "pending",
            "email": None,
            "expires_at": time.time() + expires_in,
        }
        verify_uri = f"{self.base_url}/device/verify"
        return {
            "device_code": device_code,
            "user_code": user_code,
            "device_id": device_id,
            "verification_uri": verify_uri,
            "verification_uri_complete": f"{verify_uri}?user_code={user_code}",
            "expires_in": expires_in,
            "interval": 5,
        }

    def approve_device_flow(self, user_code: str, email: str = "buihongduc132@gmail.com") -> tuple[int, dict[str, Any]]:
        if self.allowed_emails and email not in self.allowed_emails:
            return 403, {"error": "access_denied", "error_description": f"Email {email} is not allowlisted"}
        for _, record in self.device_codes.items():
            if record["user_code"] == user_code and record["expires_at"] >= time.time():
                record["status"] = "approved"
                record["email"] = email
                return 200, {"ok": True, "user_code": user_code, "device_id": record["device_id"], "email": email}
        return 404, {"error": "invalid_grant", "error_description": "Unknown or expired user_code"}

    def poll_device_flow(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        device_code = body.get("device_code", "")
        code_verifier = body.get("code_verifier", "")
        record = self.device_codes.get(device_code)
        if not record:
            return 400, {"error": "invalid_grant", "error_description": "Unknown device_code"}
        if record["expires_at"] < time.time():
            return 400, {"error": "expired_token", "error_description": "Device code expired"}
        if record["status"] != "approved":
            return 400, {"error": "authorization_pending", "error_description": "Waiting for user approval"}
        if record.get("code_challenge"):
            if not code_verifier or _pkce_s256(code_verifier) != record["code_challenge"]:
                return 400, {"error": "invalid_grant", "error_description": "PKCE code_verifier mismatch"}
        self.device_codes.pop(device_code, None)
        tok = self.issue_token(sub=f"device:{record['device_id']}", email=record["email"] or "operator@local")
        tok["device_id"] = record["device_id"]
        return 200, tok
