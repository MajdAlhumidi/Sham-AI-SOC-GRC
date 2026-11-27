"""Authentication and authorization for the SOC dashboard and API."""

import hmac
import ipaddress
import json
import os
import secrets
from collections import OrderedDict, deque
from dataclasses import dataclass
from threading import Lock
from time import monotonic
from urllib.parse import urlsplit

from fastapi import HTTPException
from starlette.requests import HTTPConnection


ROLES = frozenset({
    "SOC_READER", "SOC_ANALYST", "CASE_APPROVER", "GRC_READER",
    "GRC_EDITOR", "GRC_AUDITOR", "ADMIN", "SERVICE",
})
SESSION_COOKIE = "sham_session"
SESSION_TTL = 8 * 60 * 60
AUDIT_ROLES = ("GRC_AUDITOR", "ADMIN")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset[str]
    auth_mode: str
    token_kind: str
    actor_id: str


LOCAL_PRINCIPAL = Principal("local-demo", ROLES, "disabled", "synthetic", "local-demo:loopback")


def is_loopback(host):
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
        return (getattr(address, "ipv4_mapped", None) or address).is_loopback
    except ValueError:
        return False


def integer_setting(name, default, maximum):
    try:
        value = int(os.getenv(name, default))
    except ValueError:
        value = 0
    if not 1 <= value <= maximum:
        raise ValueError(f"{name} must be an integer between 1 and {maximum}.")
    return value


def _origin(value):
    if any(character.isspace() for character in value):
        return None
    try:
        parsed = urlsplit(value)
        if (parsed.scheme in {"http", "https"} and parsed.hostname and "*" not in parsed.netloc
                and parsed.username is None
                and parsed.password is None and (parsed.port is None or parsed.port > 0)):
            return f"{parsed.scheme}://{parsed.netloc}"
    except ValueError:
        pass
    return None


def _origins(name, defaults):
    raw = os.getenv(name)
    values = tuple(part.strip() for part in raw.split(",")) if raw is not None else defaults
    if not values or any(not value or _origin(value) != value for value in values):
        raise ValueError(f"{name} must contain exact HTTP or HTTPS origins.")
    return values


class InMemoryRateLimiter:
    """Bounded sliding window per key, shared across threads in one process."""

    def __init__(self, max_keys=10_000):
        self.max_keys = max_keys
        self.windows = OrderedDict()
        self.lock = Lock()

    def require(self, key, limit):
        with self.lock:
            now = monotonic()
            if key not in self.windows and len(self.windows) >= self.max_keys:
                # Drop expired keys first. Preserve active quotas under pressure.
                oldest_key, oldest = next(iter(self.windows.items()))
                if oldest[-1] > now - 60:
                    raise HTTPException(429, "Rate limit reached.", headers={"Retry-After": "60"})
                del self.windows[oldest_key]
            window = self.windows.setdefault(key, deque())
            while window and window[0] <= now - 60:
                window.popleft()
            if len(window) >= limit:
                wait = max(1, int(window[0] + 60 - now) + 1)
                raise HTTPException(429, "Rate limit reached.", headers={"Retry-After": str(wait)})
            window.append(now)
            self.windows.move_to_end(key)


class Security:
    def __init__(self):
        self.mode = os.getenv("SOC_API_AUTH_MODE", "disabled").strip()
        if self.mode not in {"disabled", "token"}:
            raise ValueError("SOC_API_AUTH_MODE must be disabled or token.")
        self.host = os.getenv("SOC_API_HOST", "127.0.0.1").strip()
        self.port = integer_setting("SOC_API_PORT", 8000, 65535)
        if not self.host or (self.mode == "disabled" and not is_loopback(self.host)):
            raise ValueError("Disabled authentication requires a loopback SOC_API_HOST.")
        local_origins = tuple(f"http://{host}:{self.port}" for host in ("localhost", "127.0.0.1", "[::1]"))
        self.allowed_origins = _origins("SOC_ALLOWED_ORIGINS", local_origins)
        self.websocket_origins = _origins("SOC_WEBSOCKET_ALLOWED_ORIGINS", self.allowed_origins)
        self.trusted_proxies = os.getenv("FORWARDED_ALLOW_IPS", "127.0.0.1")
        if any(part.strip() == "*" for part in self.trusted_proxies.split(",")):
            raise ValueError("FORWARDED_ALLOW_IPS must list trusted proxies explicitly.")
        cookie_secure = os.getenv("SOC_COOKIE_SECURE", "true").strip().lower()
        if cookie_secure not in {"true", "false"}:
            raise ValueError("SOC_COOKIE_SECURE must be true or false.")
        self.secure_cookie = cookie_secure == "true"
        self.export_limit = integer_setting("SOC_EXPORT_MAX_REQUESTS_PER_MINUTE", 12, 1000)
        self.credentials = self._credentials()
        if self.mode == "token" and not self.credentials:
            raise ValueError("Token authentication requires configured credentials.")
        self.review_enabled = any("SOC_ANALYST" in p.roles for p in self.credentials.values())
        self.legacy_reviews = any(p.token_kind == "review" for p in self.credentials.values())
        self.sessions = OrderedDict()
        self.session_lock = Lock()
        self.limiter = InMemoryRateLimiter()

    @staticmethod
    def _credentials():
        credentials = {}
        for env, kind, roles in (
            ("SOC_API_SERVICE_TOKEN", "service", {"SERVICE"}),
            ("SOC_REVIEW_API_TOKEN", "review", {"SOC_READER", "SOC_ANALYST"}),
            ("SOC_UI_TOKEN", "ui", {"SOC_READER", "SOC_ANALYST", "GRC_READER"}),
            ("SOC_API_BEARER_TOKEN", "admin", {"ADMIN"}),
        ):
            token = os.getenv(env, "").strip()
            if token:
                if token in credentials:
                    raise ValueError("SOC API credentials must be distinct.")
                credentials[token] = Principal(kind, frozenset(roles), "token", kind, "configured:" + kind)
        try:
            pairs = json.loads(os.getenv("SOC_API_TOKENS_JSON", "{}"), object_pairs_hook=_unique_items)
            if not isinstance(pairs, dict):
                raise ValueError
            for token, claims in pairs.items():
                if not isinstance(claims, dict):
                    raise ValueError
                subject, actor = claims["subject"], claims["actor_id"]
                role_list = claims["roles"]
                if (not token or token != token.strip() or token in credentials
                        or any(not isinstance(value, str) or not value.strip() or len(value) > 128
                               or value != value.strip() for value in (subject, actor))
                        or not isinstance(role_list, list) or not role_list
                        or not all(isinstance(role, str) and role in ROLES for role in role_list)
                        or ("SERVICE" in role_list and set(role_list) != {"SERVICE"})):
                    raise ValueError
                kind = "service" if "SERVICE" in role_list else "individual"
                if actor.startswith(("configured:", "local-demo:")):
                    raise ValueError
                credentials[token] = Principal(subject, frozenset(role_list), "token", kind, actor)
        except (ValueError, KeyError, TypeError):
            raise ValueError("Invalid or duplicate SOC_API_TOKENS_JSON credential mapping.") from None
        return credentials

    def token_principal(self, presented, *, kind=None):
        if not isinstance(presented, str) or not 1 <= len(presented) <= 2048:
            return None
        match = None
        for credential, principal in self.credentials.items():
            if hmac.compare_digest(presented.encode("utf-8"), credential.encode("utf-8")):
                if kind is None or principal.token_kind == kind:
                    match = principal
        return match

    @staticmethod
    def local(connection):
        return (connection.client is not None and is_loopback(connection.client.host)
                and is_loopback(connection.url.hostname))

    def require_transport(self, connection):
        if self.local(connection):
            return
        if self.mode == "disabled":
            raise HTTPException(403, "Disabled authentication is only available on loopback.")
        if connection.url.scheme not in {"https", "wss"}:
            raise HTTPException(403, "SHAM requires HTTPS for remote access.")

    def validate_origin(self, connection):
        origin = connection.headers.get("origin")
        if origin is None:
            origin = _origin(connection.headers.get("referer", ""))
        if origin not in self.allowed_origins:
            raise HTTPException(403, "A trusted browser origin is required.")

    def principal_for_session(self, session_id):
        if not session_id:
            return None
        with self.session_lock:
            entry = self.sessions.get(session_id)
            if entry is None:
                return None
            expiry, principal = entry
            if expiry <= monotonic():
                self.sessions.pop(session_id, None)
                return None
            return principal

    def revoke(self, session_id):
        with self.session_lock:
            self.sessions.pop(session_id, None)

    def issue_session(self, principal):
        session_id = secrets.token_urlsafe(32)
        with self.session_lock:
            if len(self.sessions) >= 2_048:
                self.sessions.popitem(last=False)
            self.sessions[session_id] = (monotonic() + SESSION_TTL, principal)
        return session_id

    def authorize(self, connection, roles, *, review=False):
        self.require_transport(connection)
        if review and not (self.legacy_reviews if self.mode == "disabled" else self.review_enabled):
            raise HTTPException(503, "Human review recording is disabled.")
        if self.mode == "disabled":
            if not review:
                if connection.scope.get("method") not in SAFE_METHODS and connection.headers.get("origin"):
                    self.validate_origin(connection)
                return LOCAL_PRINCIPAL, None
            principal = self.token_principal(connection.headers.get("x-review-token"), kind="review")
            session_id = None
        else:
            session_id = None
            authorization = connection.headers.get("authorization")
            if authorization is not None:
                scheme, _, token = authorization.partition(" ")
                principal = self.token_principal(token) if scheme.lower() == "bearer" else None
            elif review and connection.headers.get("x-review-token") is not None:
                principal = self.token_principal(connection.headers["x-review-token"], kind="review")
            else:
                session_id = connection.cookies.get(SESSION_COOKIE)
                principal = self.principal_for_session(session_id)
                if principal and connection.scope["type"] == "http" and connection.scope["method"] not in SAFE_METHODS:
                    self.validate_origin(connection)
        if principal is None:
            raise HTTPException(401, "Authentication required.", headers={"WWW-Authenticate": "Bearer"})
        if not principal.roles.intersection(roles):
            raise HTTPException(403, "Insufficient permissions.")
        return principal, session_id


def _unique_items(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate mapping keys.")
    return result


GRC_WRITES = {
    ("POST", "/api/grc/risks"), ("PATCH", "/api/grc/risks/{risk_id}"),
    ("POST", "/api/grc/risks/{risk_id}/controls/{control_id}"),
    ("POST", "/api/grc/controls"), ("PATCH", "/api/grc/controls/{control_id}"),
}
GRC_INGESTION = {
    "/api/grc/evidence", "/api/grc/integrations/wazuh/evidence",
    "/api/grc/integrations/sham-ai/assessment",
}
PUBLIC_ROUTES = {("GET", "/"), ("POST", "/api/auth/session"), ("POST", "/api/auth/logout")}
CASE_READS = {
    "/api/investigations/cases", "/api/investigations/cases/{case_id}",
    "/api/investigations/incidents/{incident_id}", "/api/investigations/evidence/{incident_id}/{ref}",
    "/api/investigations/context", "/api/investigations/audit",
    "/api/investigations/cases/{case_id}/followups",
    "/api/investigations/cases/{case_id}/followups/{turn_id}",
    "/api/investigations/comparison/dataset", "/api/investigations/comparison/trials",
    "/api/investigations/comparison/summary", "/api/investigations/comparison/trials/{trial_id}",
}
CASE_WRITES = {
    ("PUT", "/api/investigations/assets/{asset_id}"), ("PUT", "/api/investigations/changes/{change_id}"),
    ("POST", "/api/investigations/cases/{case_id}/followups"),
    ("POST", "/api/investigations/comparison/trials"),
    ("POST", "/api/investigations/comparison/trials/{trial_id}/complete"),
    ("POST", "/api/investigations/comparison/ai-trials"),
    ("POST", "/api/investigations/comparison/trials/{trial_id}/run-ai"),
}
GRC_READS = {
    "/api/grc/health", "/api/grc/risks", "/api/grc/risks/{risk_id}",
    "/api/grc/risks/{risk_id}/controls", "/api/grc/controls", "/api/grc/evidence",
    "/api/grc/compliance/summary", "/api/grc/approvals",
    "/api/grc/workspace/summary", "/api/grc/workspace/{section}",
    "/api/grc/workspace/{section}/{record_id}",
}
EXPORT_PATH = "/api/investigations/cases/{case_id}/export"


def route_roles(method, path, section=None):
    if (method, path) in PUBLIC_ROUTES:
        return ()
    if method == "GET":
        if path == EXPORT_PATH:
            return ("SOC_ANALYST", "GRC_AUDITOR")
        if path == "/api/grc/audit-logs" or (path in GRC_READS and section == "audit"):
            return AUDIT_ROLES
        if path in GRC_READS:
            return ("GRC_READER",)
        if path == "/api/incidents" or path in CASE_READS:
            return ("SOC_READER",)
    if (method, path) == ("POST", "/api/broadcast"):
        return ("SERVICE",)
    if (method, path) in CASE_WRITES or (method, path) == ("POST", "/api/reviews"):
        return ("SOC_ANALYST",)
    if (method, path) in GRC_WRITES:
        return ("GRC_EDITOR",)
    if method == "POST" and path in GRC_INGESTION:
        return ("SERVICE", "GRC_EDITOR")
    if (method, path) == ("POST", "/api/grc/approvals"):
        return ("GRC_EDITOR", "SOC_ANALYST")
    if (method, path) == ("PATCH", "/api/grc/approvals/{approval_id}/decision"):
        return ("CASE_APPROVER",)
    return None


def authorize_route(connection: HTTPConnection):
    if connection.scope["type"] == "websocket":
        return  # The WebSocket handler checks policy before accepting.
    security = connection.app.state.security
    security.require_transport(connection)
    method = connection.scope["method"]
    # Newer FastAPI versions retain nested routers' original route objects.
    # Reconstruct the registered template from the matched path and parameters.
    template = connection.scope["route"].path_format
    suffix = template.format_map(connection.path_params)
    path = connection.scope["path"]
    root = connection.scope.get("root_path", "").rstrip("/")
    if root and (path == root or path.startswith(root + "/")):
        path = path[len(root):] or "/"
    if not path.endswith(suffix):
        raise HTTPException(403, "The route could not be authorized.")
    path = path.removesuffix(suffix) + template
    roles = route_roles(method, path, connection.path_params.get("section"))
    if roles is None:
        raise HTTPException(403, "No access policy is defined for this route.")
    if not roles:
        return
    principal, _ = security.authorize(connection, roles, review=path == "/api/reviews")
    connection.state.principal = principal
    if method not in SAFE_METHODS or path == EXPORT_PATH:
        limit = security.export_limit if path == EXPORT_PATH else 240 if path == "/api/broadcast" else 60
        security.limiter.require((principal.actor_id, method, path), limit)
