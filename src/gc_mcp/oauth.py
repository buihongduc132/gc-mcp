"""OAuth 2.1 + DCR + Google OAuth Proxy + Desktop-Commander PKCE Device Flow."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padded = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _pkce_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return _b64url(digest)


def _load_dotenv_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            values[k] = v
    except Exception:
        pass
    return values


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
        env_file = _load_dotenv_file(Path.home() / ".config" / "gc-mcp" / "oauth.env")
        self.base_url = (
            base_url or os.environ.get("GC_MCP_BASE_URL", "https://bhd-main2.raven-tuatara.ts.net:18375")
        ).rstrip("/")
        self.auth_mode = (auth_mode or os.environ.get("GC_MCP_AUTH_MODE", "optional")).lower()
        self.google_client_id = (
            google_client_id
            if google_client_id is not None
            else (os.environ.get("GOOGLE_CLIENT_ID") or env_file.get("GOOGLE_CLIENT_ID", ""))
        )
        self.google_client_secret = (
            google_client_secret
            if google_client_secret is not None
            else (os.environ.get("GOOGLE_CLIENT_SECRET") or env_file.get("GOOGLE_CLIENT_SECRET", ""))
        )
        raw_emails = os.environ.get("GC_OAUTH_ALLOWED_EMAILS", "buihongduc132@gmail.com")
        self.allowed_emails = set(
            allowed_emails if allowed_emails is not None else [e.strip() for e in raw_emails.split(",") if e.strip()]
        )
        raw_secret = (
            signing_secret
            or os.environ.get("GC_OAUTH_SIGNING_SECRET")
            or env_file.get("GC_OAUTH_SIGNING_SECRET")
            or "gc-mcp-default-signing-secret-bhd-common-2026"
        )
        self.signing_secret = raw_secret.encode("utf-8")
        env_tok = os.environ.get("GC_MCP_API_TOKEN", "")
        self.static_tokens = set(static_tokens or ([env_tok] if env_tok else []))
        self.clients: dict[str, dict[str, Any]] = {}
        self.auth_codes: dict[str, dict[str, Any]] = {}
        self.device_codes: dict[str, dict[str, Any]] = {}
        self.refresh_tokens: dict[str, dict[str, Any]] = {}
        self.pending_google_states: dict[str, dict[str, Any]] = {}

    def effective_base_url(self, req_base_url: str | None = None) -> str:
        return (req_base_url or self.base_url).rstrip("/")

    def metadata(self, req_base_url: str | None = None) -> dict[str, Any]:
        burl = self.effective_base_url(req_base_url)
        return {
            "issuer": burl,
            "authorization_endpoint": f"{burl}/oauth/authorize",
            "token_endpoint": f"{burl}/oauth/token",
            "registration_endpoint": f"{burl}/oauth/register",
            "userinfo_endpoint": f"{burl}/oauth/userinfo",
            "device_authorization_endpoint": f"{burl}/device/code",
            "device_poll_endpoint": f"{burl}/device/poll",
            "scopes_supported": ["openid", "email", "profile", "mcp:tools", "gc:admin"],
            "response_types_supported": ["code"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "google_oauth_configured": bool(self.google_client_id),
            "auth_mode": self.auth_mode,
        }

    def protected_resource_metadata(self, req_base_url: str | None = None) -> dict[str, Any]:
        burl = self.effective_base_url(req_base_url)
        return {
            "resource": f"{burl}/mcp",
            "authorization_servers": [burl],
            "scopes_supported": ["openid", "email", "profile", "mcp:tools", "gc:admin"],
            "bearer_methods_supported": ["header"],
        }

    def register_client(self, body: dict[str, Any]) -> dict[str, Any]:
        client_id = f"mcp_{secrets.token_urlsafe(12)}"
        client_secret = secrets.token_urlsafe(24)
        auth_method = body.get("token_endpoint_auth_method", "none")
        record: dict[str, Any] = {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_name": body.get("client_name", "MCP Client"),
            "redirect_uris": body.get("redirect_uris", ["https://chatgpt.com/connector_platform_oauth_redirect"]),
            "grant_types": body.get("grant_types", ["authorization_code", "refresh_token"]),
            "response_types": body.get("response_types", ["code"]),
            "token_endpoint_auth_method": auth_method,
            "client_id_issued_at": int(time.time()),
            "client_secret_expires_at": 0,
        }
        self.clients[client_id] = record
        return record

    def _sign_claims(self, prefix: str, claims: dict[str, Any]) -> str:
        payload_b64 = _b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
        sig = _b64url(hmac.new(self.signing_secret, payload_b64.encode("ascii"), hashlib.sha256).digest())
        return f"{prefix}.{payload_b64}.{sig}"

    def _verify_signed(self, token: str, prefix: str) -> dict[str, Any] | None:
        if not token.startswith(f"{prefix}."):
            return None
        parts = token.split(".")
        if len(parts) != 3:
            return None
        _, payload_b64, sig = parts
        expected = _b64url(hmac.new(self.signing_secret, payload_b64.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        try:
            claims = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        except Exception:
            return None
        if int(claims.get("exp", 0)) < int(time.time()):
            return None
        return claims

    def issue_token(
        self,
        sub: str,
        email: str,
        scope: str = "openid email mcp:tools",
        ttl: int = 86400,
        req_base_url: str | None = None,
    ) -> dict[str, Any]:
        now = int(time.time())
        burl = self.effective_base_url(req_base_url)
        claims = {
            "iss": burl,
            "sub": sub,
            "email": email,
            "scope": scope,
            "iat": now,
            "exp": now + ttl,
        }
        access_token = self._sign_claims("gcmcp", claims)
        ref_claims = {
            "iss": burl,
            "sub": sub,
            "email": email,
            "scope": scope,
            "iat": now,
            "exp": now + 86400 * 30,
            "jti": secrets.token_hex(8),
        }
        refresh_token = self._sign_claims("gcref", ref_claims)
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
        claims = self._verify_signed(token, "gcmcp")
        if claims is None:
            return None
        email = claims.get("email", "")
        if self.allowed_emails and email and email not in self.allowed_emails and email != "operator@local":
            return None
        return claims

    def check_request_auth(
        self,
        auth_header: str | None,
        require_auth: bool = False,
    ) -> tuple[bool, dict[str, Any] | None]:
        token = ""
        if auth_header and auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
        if token:
            claims = self.verify_token(token)
            if claims is not None:
                return True, claims
            return False, None
        if self.auth_mode != "required" and not require_auth:
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

    def start_google_authorization(
        self,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str = "S256",
        state: str = "",
        scope: str = "openid email mcp:tools",
        req_base_url: str | None = None,
    ) -> str:
        burl = self.effective_base_url(req_base_url)
        callback_url = f"{burl}/oauth/google/callback"
        gstate = f"gstate_{secrets.token_urlsafe(20)}"
        self.pending_google_states[gstate] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "state": state,
            "scope": scope or "openid email mcp:tools",
            "callback_url": callback_url,
            "req_base_url": burl,
            "expires_at": time.time() + 600,
        }
        default_email = next(iter(self.allowed_emails), "buihongduc132@gmail.com")
        params = {
            "client_id": self.google_client_id,
            "redirect_uri": callback_url,
            "response_type": "code",
            "scope": "openid email profile",
            "state": gstate,
            "login_hint": default_email,
            "access_type": "online",
        }
        return f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"

    def complete_google_callback(self, google_code: str, gstate: str) -> tuple[int, str | dict[str, Any]]:
        pending = self.pending_google_states.pop(gstate, None)
        if not pending or pending["expires_at"] < time.time():
            return 400, {"error": "invalid_request", "error_description": "Invalid or expired OAuth state"}

        token_data = urllib.parse.urlencode(
            {
                "code": google_code,
                "client_id": self.google_client_id,
                "client_secret": self.google_client_secret,
                "redirect_uri": pending["callback_url"],
                "grant_type": "authorization_code",
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            "https://oauth2.googleapis.com/token",
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15.0) as resp:
                tok_resp = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            return 400, {"error": "invalid_grant", "error_description": f"Google token exchange failed: {err_body}"}
        except Exception as exc:
            return 502, {"error": "server_error", "error_description": str(exc)}

        email = ""
        id_token = tok_resp.get("id_token", "")
        if id_token and "." in id_token:
            try:
                claims_part = id_token.split(".")[1]
                id_claims = json.loads(_b64url_decode(claims_part).decode("utf-8"))
                email = id_claims.get("email", "")
            except Exception:
                pass

        if not email and tok_resp.get("access_token"):
            try:
                ureq = urllib.request.Request(
                    "https://www.googleapis.com/oauth2/v3/userinfo",
                    headers={"Authorization": f"Bearer {tok_resp['access_token']}"},
                )
                with urllib.request.urlopen(ureq, timeout=10.0) as uresp:
                    uinfo = json.loads(uresp.read().decode("utf-8"))
                    email = uinfo.get("email", "")
            except Exception:
                pass

        if not email:
            return 400, {"error": "invalid_grant", "error_description": "Could not determine Google account email"}

        if self.allowed_emails and email not in self.allowed_emails:
            return 403, {"error": "access_denied", "error_description": f"Email {email} is not allowlisted"}

        mcp_code = self.create_authorization_code(
            client_id=pending["client_id"],
            redirect_uri=pending["redirect_uri"],
            code_challenge=pending["code_challenge"],
            code_challenge_method=pending["code_challenge_method"],
            state=pending["state"],
            email=email,
            scope=pending["scope"],
        )
        redirect_uri = pending["redirect_uri"]
        sep = "&" if "?" in redirect_uri else "?"
        location = f"{redirect_uri}{sep}code={urllib.parse.quote(mcp_code)}"
        if pending["state"]:
            location += f"&state={urllib.parse.quote(pending['state'])}"
        return 302, location

    def exchange_code(self, body: dict[str, Any], req_base_url: str | None = None) -> tuple[int, dict[str, Any]]:
        grant_type = body.get("grant_type", "authorization_code")
        if grant_type == "refresh_token":
            rt = body.get("refresh_token", "")
            info = self.refresh_tokens.get(rt) or self._verify_signed(rt, "gcref")
            if not info:
                return 400, {"error": "invalid_grant", "error_description": "Invalid refresh_token"}
            return 200, self.issue_token(
                sub=info["sub"],
                email=info["email"],
                scope=info.get("scope", "openid email mcp:tools"),
                req_base_url=req_base_url,
            )

        code = body.get("code", "")
        verifier = body.get("code_verifier", "")
        info = self.auth_codes.pop(code, None)
        if not info or info["expires_at"] < time.time():
            return 400, {"error": "invalid_grant", "error_description": "Invalid or expired authorization code"}
        if info.get("code_challenge"):
            method = (info.get("code_challenge_method") or "S256").upper()
            expected = _pkce_s256(verifier) if method == "S256" else verifier
            if not verifier or expected != info["code_challenge"]:
                return 400, {"error": "invalid_grant", "error_description": "PKCE code_verifier mismatch"}
        email = info["email"]
        if self.allowed_emails and email not in self.allowed_emails:
            return 403, {"error": "access_denied", "error_description": f"Email {email} not in allowlist"}
        return 200, self.issue_token(
            sub=f"google:{email}",
            email=email,
            scope=info["scope"],
            req_base_url=req_base_url,
        )

    def start_device_flow(self, body: dict[str, Any], req_base_url: str | None = None) -> dict[str, Any]:
        burl = self.effective_base_url(req_base_url)
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
        verify_uri = f"{burl}/device/verify"
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

    def poll_device_flow(self, body: dict[str, Any], req_base_url: str | None = None) -> tuple[int, dict[str, Any]]:
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
        tok = self.issue_token(
            sub=f"device:{record['device_id']}",
            email=record["email"] or "operator@local",
            req_base_url=req_base_url,
        )
        tok["device_id"] = record["device_id"]
        return 200, tok
