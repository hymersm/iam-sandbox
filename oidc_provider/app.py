import base64
import hashlib
import json
import os
import secrets
import time
from typing import Optional, Dict, Any, Tuple, List
from urllib.parse import urlencode

from fastapi import APIRouter, Header
from pydantic import BaseModel

import jwt
from argon2 import PasswordHasher
from fastapi import FastAPI, Request, Form, Query, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from motor.motor_asyncio import AsyncIOMotorClient
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


# =========================
# Config
# =========================

ISSUER = os.getenv("ISSUER", "http://localhost:8000")
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "oidc")

COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
ACCESS_TOKEN_MODE = os.getenv("ACCESS_TOKEN_MODE", "jwt")  # jwt|opaque

ACCESS_TTL = int(os.getenv("ACCESS_TTL_SECONDS", "600"))
ID_TTL = int(os.getenv("ID_TTL_SECONDS", "600"))
AUTH_CODE_TTL = int(os.getenv("AUTH_CODE_TTL_SECONDS", "120"))
CSRF_TTL = int(os.getenv("CSRF_TTL_SECONDS", "600"))

AUTH_ENDPOINT = f"{ISSUER}/oauth2/authorize"
TOKEN_ENDPOINT = f"{ISSUER}/oauth2/token"
JWKS_URI = f"{ISSUER}/oauth2/jwks"
USERINFO_ENDPOINT = f"{ISSUER}/userinfo"
INTROSPECT_ENDPOINT = f"{ISSUER}/oauth2/introspect"
REVOKE_ENDPOINT = f"{ISSUER}/oauth2/revoke"

ENABLE_DEBUG_ENDPOINTS = os.getenv("ENABLE_DEBUG_ENDPOINTS", "false").lower() == "true"
DEBUG_KEY = os.getenv("DEBUG_KEY")  # if set, require X-Debug-Key header

if ENABLE_DEBUG_ENDPOINTS and not DEBUG_KEY:
    raise RuntimeError("ENABLE_DEBUG_ENDPOINTS=true requires DEBUG_KEY")

templates = Jinja2Templates(directory="templates")
ph = PasswordHasher()

def require_localhost(req: Request):
    if req.client.host not in ("127.0.0.1", "::1", "192.168.65.1"):
        raise HTTPException(403, f"debug_localhost_only [req.client.host={req.client.host}]")
    
def pkce_pair() -> dict:
    # RFC7636 verifier length: 43..128 chars; token_urlsafe(48) usually fine
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = b64url(digest)
    return {"verifier": verifier, "challenge": challenge, "method": "S256"}

def now() -> int:
    return int(time.time())


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def parse_json_list(s: str) -> list:
    return json.loads(s) if isinstance(s, str) else (s or [])


def scopes_set(scope: str) -> set:
    return set([s for s in (scope or "").split(" ") if s])


def pkce_verify(verifier: str, challenge: str, method: str) -> bool:
    if method == "plain":
        return secrets.compare_digest(verifier, challenge)
    if method == "S256":
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        computed = b64url(digest)
        return secrets.compare_digest(computed, challenge)
    return False


def parse_basic_auth(req: Request) -> Optional[Tuple[str, str]]:
    auth = req.headers.get("authorization", "")
    if not auth.lower().startswith("basic "):
        return None
    b64 = auth.split(" ", 1)[1].strip()
    try:
        raw = base64.b64decode(b64).decode("utf-8")
    except Exception:
        return None
    if ":" not in raw:
        return None
    cid, sec = raw.split(":", 1)
    return cid, sec


def jwk_to_rsa_public_key(jwk: dict):
    if jwk.get("kty") != "RSA":
        raise ValueError("Only RSA supported in this lab")

    def _int_from_b64url(x: str) -> int:
        pad = "=" * (-len(x) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(x + pad), "big")

    n = _int_from_b64url(jwk["n"])
    e = _int_from_b64url(jwk["e"])
    return rsa.RSAPublicNumbers(e, n).public_key()


# =========================
# Basic in-process rate limiting (lab)
# =========================

RATE_BUCKETS: Dict[str, List[int]] = {}

def ratelimit(key: str, limit: int, window_seconds: int) -> None:
    t = now()
    bucket = RATE_BUCKETS.get(key, [])
    bucket = [x for x in bucket if t - x < window_seconds]
    if len(bucket) >= limit:
        raise HTTPException(status_code=429, detail="rate_limit_exceeded")
    bucket.append(t)
    RATE_BUCKETS[key] = bucket


# =========================
# App + Mongo
# =========================

app = FastAPI(title="OIDC/OAuth2 Server (Mongo, hardened lab)", version="0.3.0")

debug = APIRouter(prefix="/debug", tags=["debug"])

mongo = AsyncIOMotorClient(MONGO_URL)
db = mongo[MONGO_DB]

# Collections
col_users = db["users"]
col_clients = db["clients"]
col_sessions = db["sessions"]
col_csrf = db["csrf_tokens"]
col_pending = db["pending_consents"]
col_codes = db["auth_codes"]
col_refresh = db["refresh_tokens"]
col_access_opaque = db["access_tokens_opaque"]
col_keys = db["keys"]
col_jti = db["jti_denylist"]  # optional denylist for JWT access tokens
col_scopes = db["scope_definitions"]
col_claims = db["claim_definitions"]

# =========================
# Middleware: security headers
# =========================

@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    return resp


# =========================
# Bootstrap/Indexes/Seed
# =========================

async def ensure_indexes():
    await col_sessions.create_index("exp", expireAfterSeconds=0)
    await col_csrf.create_index("exp", expireAfterSeconds=0)
    await col_pending.create_index("exp", expireAfterSeconds=0)
    await col_codes.create_index("exp", expireAfterSeconds=0)
    await col_refresh.create_index("exp", expireAfterSeconds=0)
    await col_access_opaque.create_index("exp", expireAfterSeconds=0)
    await col_jti.create_index("exp", expireAfterSeconds=0)

    await col_clients.create_index("client_id", unique=True)
    await col_users.create_index("username", unique=True)
    await col_keys.create_index("kid", unique=True)


def generate_rsa_keypair_jwk(kid: str) -> Tuple[str, dict]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")

    pub = key.public_key().public_numbers()
    n = b64url(pub.n.to_bytes((pub.n.bit_length() + 7)//8, "big"))
    e = b64url(pub.e.to_bytes((pub.e.bit_length() + 7)//8, "big"))
    jwk = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": e}
    return priv_pem, jwk


async def seed_if_empty():
    # users
    if await col_users.count_documents({}) == 0:
        await col_users.insert_many([
            {
                "username": "alice",
                "password_hash": ph.hash("password"),
                "sub": "user-alice-001",
                "name": "Alice Example",
                "email": "alice@example.com",
            },
            {
                "username": "bob",
                "password_hash": ph.hash("password"),
                "sub": "user-bob-001",
                "name": "Bob Example",
                "email": "bob@example.com",
            },
        ])

    # clients
    if await col_clients.count_documents({}) == 0:
        await col_clients.insert_many([
            # SPA public client
            {
                "client_id": "demo-spa",
                "client_type": "public",
                "redirect_uris": ["http://localhost:5173/callback", "http://localhost:3000/callback"],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "client_secret": None,
                "jwk": None,  # for private_key_jwt
                "allowed_scopes": ["openid", "profile", "email", "offline_access"],
                "allowed_audiences": ["frontend-api", "downstream-api"],
                "allowed_resources": ["https://api.local/patients", "https://downstream.local/data"],
                "allow_token_exchange": False,
            },
            # backend client_secret_basic
            {
                "client_id": "demo-backend-secret",
                "client_type": "confidential",
                "redirect_uris": ["http://localhost:8080/callback"],
                "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "client_secret_basic",
                "client_secret": "supersecret",
                "jwk": None,
                "allowed_scopes": ["openid", "profile", "email", "offline_access"],
                "allowed_audiences": ["frontend-api", "downstream-api"],
                "allowed_resources": ["https://api.local/patients", "https://downstream.local/data"],
                "allow_token_exchange": True,
            },
            # backend private_key_jwt
            {
                "client_id": "demo-backend-pkjwt",
                "client_type": "confidential",
                "redirect_uris": ["http://localhost:8081/callback"],
                "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "private_key_jwt",
                "client_secret": None,
                "jwk": None,  # set via /admin/set-client-jwk
                "allowed_scopes": ["openid", "profile", "email", "offline_access"],
                "allowed_audiences": ["frontend-api", "downstream-api"],
                "allowed_resources": ["https://api.local/patients", "https://downstream.local/data"],
                "allow_token_exchange": True,
            },
        ])

    # keys
    if await col_keys.count_documents({"active": True}) == 0:
        kid = f"lab-{now()}"
        priv_pem, jwk = generate_rsa_keypair_jwk(kid)
        await col_keys.insert_one({
            "kid": kid,
            "private_pem": priv_pem,
            "public_jwk": jwk,
            "active": True,
            "created_at": now(),
        })


@app.on_event("startup")
async def startup():
    await ensure_indexes()
    await seed_if_empty()


# =========================
# Auth helpers
# =========================

async def get_cookie_sid(req: Request) -> Optional[str]:
    return req.cookies.get("oidc_sid")


async def require_session(req: Request) -> dict:
    sid = await get_cookie_sid(req)
    if not sid:
        raise HTTPException(401, "not_logged_in")
    row = await col_sessions.find_one({"sid": sid})
    if not row:
        raise HTTPException(401, "invalid_session")
    return row


async def require_client(client_id: str) -> dict:
    c = await col_clients.find_one({"client_id": client_id})
    if not c:
        raise HTTPException(400, "invalid_client")
    return c


def require_redirect_uri(client: dict, redirect_uri: str) -> None:
    if redirect_uri not in client.get("redirect_uris", []):
        raise HTTPException(400, "invalid_redirect_uri")


def validate_scopes(client: dict, requested_scope: str) -> str:
    allowed = set(client.get("allowed_scopes", []))
    req = [s for s in (requested_scope or "").split(" ") if s]
    for s in req:
        if s not in allowed:
            raise HTTPException(400, "invalid_scope")
    return " ".join(req)


def validate_audience_resource(client: dict, audience: Optional[str], resource: Optional[str]) -> None:
    if audience and audience not in set(client.get("allowed_audiences", [])):
        raise HTTPException(400, "invalid_target: audience_not_allowed")
    if resource and resource not in set(client.get("allowed_resources", [])):
        raise HTTPException(400, "invalid_target: resource_not_allowed")


async def active_signing_key() -> Tuple[str, str]:
    row = await col_keys.find_one({"active": True}, sort=[("created_at", -1)])
    if not row:
        raise HTTPException(500, "no_signing_key")
    return row["kid"], row["private_pem"]


async def sign_jwt(claims: dict, ttl: int) -> str:
    kid, priv_pem = await active_signing_key()
    payload = dict(claims)
    payload.setdefault("iss", ISSUER)
    payload.setdefault("iat", now())
    payload.setdefault("exp", now() + ttl)
    return jwt.encode(payload, priv_pem, algorithm="RS256", headers={"kid": kid, "typ": "JWT"})


async def verify_private_key_jwt(client: dict, client_assertion: str) -> bool:
    jwk = client.get("jwk")
    if not jwk:
        return False
    try:
        pub = jwk_to_rsa_public_key(jwk)
        claims = jwt.decode(
            client_assertion,
            pub,
            algorithms=["RS256"],
            audience=TOKEN_ENDPOINT,
            options={"require": ["exp", "iat", "aud"]},
        )
    except jwt.PyJWTError:
        return False
    cid = client["client_id"]
    return claims.get("iss") == cid and claims.get("sub") == cid


async def authenticate_client(
    req: Request,
    client: dict,
    body_client_id: Optional[str],
    client_assertion: Optional[str],
    client_assertion_type: Optional[str],
) -> str:
    """
    Returns the authenticated client_id.
    - If Basic auth is present, infer client_id.
    - If body_client_id present too, ensure match.
    - For private_key_jwt, require assertion.
    """
    method = client.get("token_endpoint_auth_method", "none")
    cid = client["client_id"]

    basic = parse_basic_auth(req)

    if method == "none":
        if client.get("client_type") != "public":
            raise HTTPException(400, "invalid_client")
        if body_client_id and body_client_id != cid:
            raise HTTPException(400, "invalid_client")
        return cid

    if method == "client_secret_basic":
        if not basic:
            raise HTTPException(401, "invalid_client")
        basic_cid, basic_secret = basic
        if basic_cid != cid:
            raise HTTPException(401, "invalid_client")
        if body_client_id and body_client_id != cid:
            raise HTTPException(400, "invalid_client")
        if not secrets.compare_digest(basic_secret, client.get("client_secret") or ""):
            raise HTTPException(401, "invalid_client")
        return cid

    if method == "private_key_jwt":
        if body_client_id and body_client_id != cid:
            raise HTTPException(400, "invalid_client")
        if client_assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
            raise HTTPException(400, "invalid_client")
        if not client_assertion:
            raise HTTPException(400, "invalid_client")
        ok = await verify_private_key_jwt(client, client_assertion)
        if not ok:
            raise HTTPException(401, "invalid_client")
        return cid

    raise HTTPException(400, "invalid_client")


# =========================
# CSRF helpers (double submit + server binding)
# =========================

async def mint_csrf(sid: str) -> str:
    token = secrets.token_urlsafe(24)
    await col_csrf.insert_one({"token": token, "sid": sid, "exp": now() + CSRF_TTL})
    return token


async def verify_csrf(req: Request, form_csrf: str, sid: str) -> None:
    cookie = req.cookies.get("oidc_csrf")
    if not cookie or not form_csrf:
        raise HTTPException(403, "csrf_missing")
    if not secrets.compare_digest(cookie, form_csrf):
        raise HTTPException(403, "csrf_mismatch")

    doc = await col_csrf.find_one({"token": form_csrf, "sid": sid})
    if not doc:
        raise HTTPException(403, "csrf_invalid")
    # one-time use
    await col_csrf.delete_one({"token": form_csrf})


# =========================
# Token minting (access/id/refresh)
# =========================

async def mint_access_token(
    sub: str,
    client_id: str,
    scope: str,
    audience: Optional[str],
    resource: Optional[str],
    actor: Optional[dict] = None,
) -> Tuple[str, int]:
    exp = now() + ACCESS_TTL

    if ACCESS_TOKEN_MODE == "opaque":
        tok = secrets.token_urlsafe(32)
        await col_access_opaque.insert_one({
            "token": tok,
            "client_id": client_id,
            "sub": sub,
            "scope": scope,
            "aud": audience or client_id,
            "resource": resource,
            "exp": exp,
            "revoked": False,
        })
        return tok, ACCESS_TTL

    jti = secrets.token_urlsafe(16)
    claims: Dict[str, Any] = {
        "sub": sub,
        "client_id": client_id,
        "scope": scope,
        "typ": "access_token",
        "aud": audience or client_id,
        "resource": resource,
        "jti": jti,
    }
    if actor:
        claims["act"] = actor
    tok = await sign_jwt(claims, ttl=ACCESS_TTL)
    return tok, ACCESS_TTL


async def mint_id_token(sub: str, client_id: str, nonce: Optional[str]) -> str:
    claims = {"sub": sub, "aud": client_id, "typ": "id_token"}
    if nonce:
        claims["nonce"] = nonce
    return await sign_jwt(claims, ttl=ID_TTL)


# Refresh tokens: rt_id.rt_secret; store hash of secret, rotate + reuse detection
def hash_refresh_secret(secret: str) -> str:
    return ph.hash(secret)

def verify_refresh_secret(hash_: str, secret: str) -> bool:
    try:
        return ph.verify(hash_, secret)
    except Exception:
        return False

async def mint_refresh_token(sub: str, client_id: str, scope: str, family_id: Optional[str] = None) -> str:
    rt_id = secrets.token_urlsafe(10)
    rt_secret = secrets.token_urlsafe(32)
    fam = family_id or secrets.token_urlsafe(10)

    await col_refresh.insert_one({
        "rt_id": rt_id,
        "secret_hash": hash_refresh_secret(rt_secret),
        "family_id": fam,
        "client_id": client_id,
        "sub": sub,
        "scope": scope,
        "created_at": now(),
        "exp": now() + (7 * 24 * 60 * 60),
        "revoked": False,
        "replaced_by_rt_id": None,
        "reuse_detected": False,
    })
    return f"{rt_id}.{rt_secret}"


async def revoke_refresh_family(family_id: str) -> None:
    await col_refresh.update_many({"family_id": family_id}, {"$set": {"revoked": True}})


async def redeem_refresh_token(presented: str, client_id: str) -> Tuple[dict, str]:
    if "." not in presented:
        raise HTTPException(400, "invalid_grant")
    rt_id, rt_secret = presented.split(".", 1)

    doc = await col_refresh.find_one({"rt_id": rt_id})
    if not doc or doc.get("revoked"):
        raise HTTPException(400, "invalid_grant")

    if doc["client_id"] != client_id:
        raise HTTPException(400, "invalid_grant")

    if doc.get("replaced_by_rt_id"):
        # reuse attempt (token already used)
        await col_refresh.update_one({"rt_id": rt_id}, {"$set": {"reuse_detected": True}})
        await revoke_refresh_family(doc["family_id"])
        raise HTTPException(400, "invalid_grant: refresh_token_reuse_detected")

    if not verify_refresh_secret(doc["secret_hash"], rt_secret):
        raise HTTPException(400, "invalid_grant")

    # rotate
    new_token = await mint_refresh_token(doc["sub"], client_id, doc["scope"], family_id=doc["family_id"])
    new_rt_id = new_token.split(".", 1)[0]

    await col_refresh.update_one({"rt_id": rt_id}, {"$set": {"replaced_by_rt_id": new_rt_id}})
    return doc, new_token


# =========================
# Discovery + JWKS
# =========================

@app.get("/.well-known/openid-configuration")
async def discovery():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": AUTH_ENDPOINT,
        "token_endpoint": TOKEN_ENDPOINT,
        "jwks_uri": JWKS_URI,
        "userinfo_endpoint": USERINFO_ENDPOINT,
        "introspection_endpoint": INTROSPECT_ENDPOINT,
        "revocation_endpoint": REVOKE_ENDPOINT,
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "private_key_jwt"],
        "code_challenge_methods_supported": ["S256", "plain"],
    }


@app.get("/oauth2/jwks")
async def jwks():
    keys = []
    async for r in col_keys.find({"active": True}):
        keys.append(r["public_jwk"])
    return {"keys": keys}


# =========================
# UI: login + consent (CSRF protected)
# =========================

@app.get("/ui/login", response_class=HTMLResponse)
async def ui_login(request: Request, return_to: str = Query("/")):
    # Pre-login CSRF bound to a temporary sid placeholder
    pre_sid = request.cookies.get("oidc_pre") or secrets.token_urlsafe(12)
    csrf = await mint_csrf(pre_sid)

    resp = templates.TemplateResponse("login.html", {"request": request, "return_to": return_to, "csrf": csrf, "error": None})
    resp.set_cookie("oidc_pre", pre_sid, httponly=True, samesite="lax", secure=COOKIE_SECURE)
    resp.set_cookie("oidc_csrf", csrf, httponly=True, samesite="lax", secure=COOKIE_SECURE)
    return resp


@app.post("/ui/login")
async def ui_login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    return_to: str = Form("/"),
    csrf: str = Form(...),
):
    ratelimit(f"login:{request.client.host}", limit=10, window_seconds=60)

    pre_sid = request.cookies.get("oidc_pre")
    if not pre_sid:
        raise HTTPException(403, "csrf_invalid")
    await verify_csrf(request, csrf, pre_sid)

    u = await col_users.find_one({"username": username})
    if not u:
        return templates.TemplateResponse("login.html", {"request": request, "return_to": return_to, "csrf": csrf, "error": "Invalid credentials"}, status_code=401)

    try:
        ph.verify(u["password_hash"], password)
    except Exception:
        return templates.TemplateResponse("login.html", {"request": request, "return_to": return_to, "csrf": csrf, "error": "Invalid credentials"}, status_code=401)

    # session fixation protection: mint fresh sid on login
    sid = secrets.token_urlsafe(24)
    await col_sessions.insert_one({"sid": sid, "username": username, "exp": now() + 8 * 60 * 60})

    resp = RedirectResponse(url=return_to, status_code=302)
    resp.set_cookie("oidc_sid", sid, httponly=True, samesite="lax", secure=COOKIE_SECURE, max_age=8 * 60 * 60)
    resp.delete_cookie("oidc_pre")
    return resp


@app.get("/ui/consent", response_class=HTMLResponse)
async def ui_consent(request: Request, consent_id: str = Query(...)):
    sess = await require_session(request)
    pc = await col_pending.find_one({"consent_id": consent_id, "sid": sess["sid"]})
    if not pc:
        raise HTTPException(400, "invalid_consent")

    csrf = await mint_csrf(sess["sid"])
    resp = templates.TemplateResponse("consent.html", {
        "request": request,
        "consent_id": consent_id,
        "client_id": pc["client_id"],
        "scope": pc["scope"],
        "audience": pc.get("audience"),
        "resource": pc.get("resource"),
        "csrf": csrf,
    })
    resp.set_cookie("oidc_csrf", csrf, httponly=True, samesite="lax", secure=COOKIE_SECURE)
    return resp


@app.post("/ui/consent")
async def ui_consent_post(
    request: Request,
    consent_id: str = Form(...),
    decision: str = Form(...),
    csrf: str = Form(...),
):
    sess = await require_session(request)
    await verify_csrf(request, csrf, sess["sid"])

    pc = await col_pending.find_one({"consent_id": consent_id, "sid": sess["sid"]})
    if not pc:
        raise HTTPException(400, "invalid_consent")

    if decision != "allow":
        params = {"error": "access_denied"}
        if pc.get("state"):
            params["state"] = pc["state"]
        await col_pending.delete_one({"consent_id": consent_id})
        return RedirectResponse(url=f"{pc['redirect_uri']}?{urlencode(params)}", status_code=302)

    # issue auth code
    code = secrets.token_urlsafe(32)
    user = await col_users.find_one({"username": sess["username"]})

    await col_codes.insert_one({
        "code": code,
        "client_id": pc["client_id"],
        "redirect_uri": pc["redirect_uri"],
        "scope": pc["scope"],
        "sub": user["sub"],
        "nonce": pc.get("nonce"),
        "code_challenge": pc["code_challenge"],
        "code_challenge_method": pc["code_challenge_method"],
        "audience": pc.get("audience"),
        "resource": pc.get("resource"),
        "exp": now() + AUTH_CODE_TTL,
        "used": False,
    })
    await col_pending.delete_one({"consent_id": consent_id})

    params = {"code": code}
    if pc.get("state"):
        params["state"] = pc["state"]
    return RedirectResponse(url=f"{pc['redirect_uri']}?{urlencode(params)}", status_code=302)


# =========================
# OAuth2: authorize
# =========================

@app.get("/oauth2/authorize")
async def authorize(
    request: Request,
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query("openid profile email"),
    state: Optional[str] = Query(None),
    nonce: Optional[str] = Query(None),
    code_challenge: str = Query(...),
    code_challenge_method: str = Query("S256"),
    audience: Optional[str] = Query(None),
    resource: Optional[str] = Query(None),
):
    # best practice hardening
    if response_type != "code":
        raise HTTPException(400, "unsupported_response_type")
    if not state:
        raise HTTPException(400, "invalid_request: state_required")
    if code_challenge_method not in ("S256", "plain"):
        raise HTTPException(400, "invalid_request")
    if "openid" in scopes_set(scope) and not nonce:
        raise HTTPException(400, "invalid_request: nonce_required_for_openid")

    client = await require_client(client_id)
    require_redirect_uri(client, redirect_uri)

    # login gate
    sid = await get_cookie_sid(request)
    if not sid or not await col_sessions.find_one({"sid": sid}):
        return_to = str(request.url)
        return RedirectResponse(url=f"/ui/login?{urlencode({'return_to': return_to})}", status_code=302)

    # validate request
    scope = validate_scopes(client, scope)
    validate_audience_resource(client, audience, resource)

    # PKCE required for public clients
    if client.get("client_type") == "public" and not code_challenge:
        raise HTTPException(400, "invalid_request: pkce_required")

    consent_id = secrets.token_urlsafe(16)
    await col_pending.insert_one({
        "consent_id": consent_id,
        "sid": sid,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "audience": audience,
        "resource": resource,
        "exp": now() + 10 * 60,
    })
    return RedirectResponse(url=f"/ui/consent?{urlencode({'consent_id': consent_id})}", status_code=302)


# =========================
# Token endpoint: code / refresh / exchange
# =========================

@app.post("/oauth2/token")
async def token(
    request: Request,
    grant_type: str = Form(...),

    # client auth
    client_id: Optional[str] = Form(None),
    client_assertion: Optional[str] = Form(None),
    client_assertion_type: Optional[str] = Form(None),

    # code flow
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),

    # refresh
    refresh_token: Optional[str] = Form(None),

    # resource indicators
    audience: Optional[str] = Form(None),
    resource: Optional[str] = Form(None),

    # RFC8693
    subject_token: Optional[str] = Form(None),
    subject_token_type: Optional[str] = Form(None),
    actor_token: Optional[str] = Form(None),
    actor_token_type: Optional[str] = Form(None),
    scope: Optional[str] = Form(None),
):
    ratelimit(f"token:{request.client.host}", limit=30, window_seconds=60)

    # Infer client_id from Basic auth if not in body
    basic = parse_basic_auth(request)
    inferred_cid = basic[0] if basic else None
    cid = client_id or inferred_cid
    if not cid:
        raise HTTPException(400, "invalid_client")

    client = await require_client(cid)
    await authenticate_client(request, client, client_id, client_assertion, client_assertion_type)

    # validate audience/resource for token requests too (client allow-list)
    validate_audience_resource(client, audience, resource)

    if grant_type == "authorization_code":
        if not code or not redirect_uri or not code_verifier:
            raise HTTPException(400, "invalid_request")
        require_redirect_uri(client, redirect_uri)

        ac = await col_codes.find_one({"code": code})
        if not ac or ac.get("used"):
            raise HTTPException(400, "invalid_grant")
        if ac["client_id"] != cid or ac["redirect_uri"] != redirect_uri:
            raise HTTPException(400, "invalid_grant")

        if not pkce_verify(code_verifier, ac["code_challenge"], ac["code_challenge_method"]):
            raise HTTPException(400, "invalid_grant: pkce_failed")

        # audience/resource must match what was consented
        if (audience or None) != (ac.get("audience") or None):
            raise HTTPException(400, "invalid_target: audience_mismatch")
        if (resource or None) != (ac.get("resource") or None):
            raise HTTPException(400, "invalid_target: resource_mismatch")

        await col_codes.update_one({"code": code}, {"$set": {"used": True}})

        access_token, expires_in = await mint_access_token(ac["sub"], cid, ac["scope"], ac.get("audience"), ac.get("resource"))
        id_token = await mint_id_token(ac["sub"], cid, ac.get("nonce"))

        out = {
            "token_type": "Bearer",
            "access_token": access_token,
            "expires_in": expires_in,
            "scope": ac["scope"],
            "id_token": id_token,
        }

        if "offline_access" in scopes_set(ac["scope"]):
            # If you want to forbid refresh tokens to SPA, enforce it here.
            out["refresh_token"] = await mint_refresh_token(ac["sub"], cid, ac["scope"])

        return JSONResponse(out)

    if grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(400, "invalid_request")
        doc, new_rt = await redeem_refresh_token(refresh_token, cid)

        access_token, expires_in = await mint_access_token(doc["sub"], cid, doc["scope"], audience, resource)
        id_token = await mint_id_token(doc["sub"], cid, None)

        return JSONResponse({
            "token_type": "Bearer",
            "access_token": access_token,
            "expires_in": expires_in,
            "scope": doc["scope"],
            "id_token": id_token,
            "refresh_token": new_rt,
        })

    if grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
        if not client.get("allow_token_exchange"):
            raise HTTPException(400, "unauthorized_client")
        if not subject_token or not subject_token_type:
            raise HTTPException(400, "invalid_request")

        sub, subject_scope = await introspect_subject_for_exchange(subject_token)
        requested_scope = scope or subject_scope

        # downscope enforcement
        if not scopes_set(requested_scope).issubset(scopes_set(subject_scope)):
            raise HTTPException(400, "invalid_scope")

        actor_claim = None
        if actor_token:
            actor_sub, _ = await introspect_subject_for_exchange(actor_token)
            actor_claim = {"sub": actor_sub}

        exchanged_access, expires_in = await mint_access_token(
            sub=sub,
            client_id=cid,
            scope=requested_scope,
            audience=audience,
            resource=resource,
            actor=actor_claim,
        )

        return JSONResponse({
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "access_token": exchanged_access,
            "expires_in": expires_in,
            "scope": requested_scope,
        })

    raise HTTPException(400, "unsupported_grant_type")


async def introspect_subject_for_exchange(token: str) -> Tuple[str, str]:
    # opaque mode
    if ACCESS_TOKEN_MODE == "opaque":
        row = await col_access_opaque.find_one({"token": token, "revoked": False})
        if not row or row["exp"] <= now():
            raise HTTPException(400, "invalid_subject_token")
        return row["sub"], row.get("scope", "")

    # jwt mode: verify against any active key
    async for r in col_keys.find({"active": True}):
        pub = jwk_to_rsa_public_key(r["public_jwk"])
        try:
            claims = jwt.decode(token, pub, algorithms=["RS256"], issuer=ISSUER, options={"verify_aud": False})
            if claims.get("typ") != "access_token":
                raise HTTPException(400, "invalid_subject_token_type")
            return claims["sub"], claims.get("scope", "")
        except jwt.PyJWTError:
            continue
    raise HTTPException(400, "invalid_subject_token")


# =========================
# Introspection (confidential clients only by default)
# =========================

@app.post("/oauth2/introspect")
async def introspect(
    request: Request,
    token: str = Form(...),
    client_id: Optional[str] = Form(None),
    client_assertion: Optional[str] = Form(None),
    client_assertion_type: Optional[str] = Form(None),
):
    ratelimit(f"introspect:{request.client.host}", limit=120, window_seconds=60)

    basic = parse_basic_auth(request)
    inferred_cid = basic[0] if basic else None
    cid = client_id or inferred_cid
    if not cid:
        raise HTTPException(400, "invalid_client")

    client = await require_client(cid)

    # enforce confidential clients for introspection
    if client.get("client_type") != "confidential":
        raise HTTPException(403, "insufficient_client_privileges")

    await authenticate_client(request, client, client_id, client_assertion, client_assertion_type)

    if ACCESS_TOKEN_MODE == "opaque":
        row = await col_access_opaque.find_one({"token": token})
        if not row or row.get("revoked") or row["exp"] <= now():
            return JSONResponse({"active": False})
        return JSONResponse({
            "active": True,
            "iss": ISSUER,
            "sub": row["sub"],
            "client_id": row["client_id"],
            "scope": row.get("scope", ""),
            "exp": row["exp"],
            "aud": row.get("aud"),
            "resource": row.get("resource"),
        })

    async for r in col_keys.find({"active": True}):
        pub = jwk_to_rsa_public_key(r["public_jwk"])
        try:
            claims = jwt.decode(token, pub, algorithms=["RS256"], issuer=ISSUER, options={"verify_aud": False})
            # Optional JWT denylist check
            jti = claims.get("jti")
            if jti and await col_jti.find_one({"jti": jti}):
                return JSONResponse({"active": False})
            return JSONResponse({"active": True, **claims})
        except jwt.PyJWTError:
            continue

    return JSONResponse({"active": False})


# =========================
# Revocation (refresh + opaque; JWT -> jti denylist best-effort)
# =========================

@app.post("/oauth2/revoke")
async def revoke(
    request: Request,
    token: str = Form(...),
    token_type_hint: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_assertion: Optional[str] = Form(None),
    client_assertion_type: Optional[str] = Form(None),
):
    ratelimit(f"revoke:{request.client.host}", limit=60, window_seconds=60)

    basic = parse_basic_auth(request)
    inferred_cid = basic[0] if basic else None
    cid = client_id or inferred_cid
    if not cid:
        raise HTTPException(400, "invalid_client")

    client = await require_client(cid)
    await authenticate_client(request, client, client_id, client_assertion, client_assertion_type)

    # refresh token
    if "." in token:
        rt_id = token.split(".", 1)[0]
        doc = await col_refresh.find_one({"rt_id": rt_id, "client_id": cid})
        if doc:
            await revoke_refresh_family(doc["family_id"])
        return JSONResponse({"revoked": True})

    # opaque access token
    await col_access_opaque.update_one({"token": token, "client_id": cid}, {"$set": {"revoked": True}})

    # JWT access token: if you pass a JWT, best-effort denylist by jti
    if token.count(".") == 2:
        try:
            # decode without signature (we only need jti); in a stricter implementation, verify signature
            claims = jwt.decode(token, options={"verify_signature": False})
            jti = claims.get("jti")
            exp = claims.get("exp")
            if jti and exp:
                await col_jti.insert_one({"jti": jti, "exp": exp})
        except Exception:
            pass

    return JSONResponse({"revoked": True})


# =========================
# UserInfo
# =========================

@app.get("/userinfo")
async def userinfo(request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "missing_bearer_token")
    token = auth.split(" ", 1)[1].strip()

    if ACCESS_TOKEN_MODE == "opaque":
        row = await col_access_opaque.find_one({"token": token, "revoked": False})
        if not row or row["exp"] <= now():
            raise HTTPException(401, "invalid_token")
        u = await col_users.find_one({"sub": row["sub"]})
        if not u:
            raise HTTPException(401, "unknown_sub")
        return {"sub": u["sub"], "name": u["name"], "email": u["email"]}

    async for r in col_keys.find({"active": True}):
        pub = jwk_to_rsa_public_key(r["public_jwk"])
        try:
            claims = jwt.decode(token, pub, algorithms=["RS256"], issuer=ISSUER, options={"verify_aud": False})
            if claims.get("typ") != "access_token":
                raise HTTPException(401, "invalid_token")
            jti = claims.get("jti")
            if jti and await col_jti.find_one({"jti": jti}):
                raise HTTPException(401, "invalid_token")
            u = await col_users.find_one({"sub": claims.get("sub")})
            if not u:
                raise HTTPException(401, "unknown_sub")
            return {"sub": u["sub"], "name": u["name"], "email": u["email"]}
        except jwt.PyJWTError:
            continue
    raise HTTPException(401, "invalid_token")


# =========================
# Admin: rotate keys + set client jwk
# =========================

@app.post("/admin/rotate-keys")
async def admin_rotate_keys(deactivate_previous: bool = Form(True)):
    if deactivate_previous:
        await col_keys.update_many({"active": True}, {"$set": {"active": False}})

    kid = f"lab-{now()}"
    priv_pem, jwk = generate_rsa_keypair_jwk(kid)
    await col_keys.insert_one({
        "kid": kid,
        "private_pem": priv_pem,
        "public_jwk": jwk,
        "active": True,
        "created_at": now(),
    })
    return {"kid": kid, "jwks_uri": JWKS_URI}


@app.post("/admin/set-client-jwk")
async def admin_set_client_jwk(client_id: str = Form(...), jwk_json: str = Form(...)):
    try:
        jwk = json.loads(jwk_json)
    except Exception:
        raise HTTPException(400, "invalid_jwk_json")
    res = await col_clients.update_one({"client_id": client_id}, {"$set": {"jwk": jwk}})
    if res.matched_count == 0:
        raise HTTPException(404, "client_not_found")
    return {"updated": True, "client_id": client_id}

# =========================
# Debug: helpers for development and testing (protected by DEBUG_KEY if set)
# =========================

def require_debug_key(x_debug_key: Optional[str]) -> None:
    if DEBUG_KEY and (not x_debug_key or not secrets.compare_digest(x_debug_key, DEBUG_KEY)):
        raise HTTPException(status_code=401, detail="debug_key_required")

@debug.get("/health")
async def debug_health():
    return {"ok": True, "ts": now()}

@debug.get("/config")
async def debug_config(request: Request, x_debug_key: Optional[str] = Header(None)):
    require_localhost(request)
    require_debug_key(x_debug_key)
    return {
        "issuer": ISSUER,
        "access_token_mode": ACCESS_TOKEN_MODE,
        "cookie_secure": COOKIE_SECURE,
        "access_ttl": ACCESS_TTL,
        "id_ttl": ID_TTL,
        "auth_code_ttl": AUTH_CODE_TTL,
        "csrf_ttl": CSRF_TTL,
    }

@debug.get("/pkce")
async def debug_pkce(request: Request, x_debug_key: Optional[str] = Header(None)):
    """
    Dev helper only. Not part of OAuth/OIDC spec.
    Use this to get verifier/challenge pairs for curl demos.
    """
    require_localhost(request)
    require_debug_key(x_debug_key)
    return pkce_pair()

@debug.get("/keys")
async def debug_keys(request: Request, x_debug_key: Optional[str] = Header(None)):
    """
    Shows active signing key ids (safe). Never returns private keys.
    """
    require_localhost(request)
    require_debug_key(x_debug_key)
    kids = []
    async for r in col_keys.find({"active": True}, {"kid": 1, "_id": 0}):
        kids.append(r["kid"])
    return {"active_kids": kids}

class JwtDecodeIn(BaseModel):
    token: str

@debug.post("/jwt/decode")
async def debug_jwt_decode(request: Request, payload: JwtDecodeIn, x_debug_key: Optional[str] = Header(None)):
    """
    Decodes JWT WITHOUT verifying signature.
    Dev helper for inspecting claims.
    """
    require_localhost(request)
    require_debug_key(x_debug_key)
    try:
        header = jwt.get_unverified_header(payload.token)
        claims = jwt.decode(payload.token, options={"verify_signature": False})
        return {"header": header, "claims": claims}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"decode_failed: {e}")

class ClientAssertionIn(BaseModel):
    client_id: str
    private_pem: str
    kid: str | None = None
    aud: str | None = None
    ttl_seconds: int = 300

@debug.post("/client-assertion")
async def debug_client_assertion(payload: ClientAssertionIn, request: Request, x_debug_key: str | None = Header(None)):
    require_localhost(request)
    require_debug_key(x_debug_key)

    aud = payload.aud or TOKEN_ENDPOINT
    now_ts = now()
    claims = {
        "iss": payload.client_id,
        "sub": payload.client_id,
        "aud": aud,
        "iat": now_ts,
        "exp": now_ts + int(payload.ttl_seconds),
        "jti": f"jti-{secrets.token_urlsafe(12)}",
    }
    headers = {}
    if payload.kid:
        headers["kid"] = payload.kid

    try:
        token = jwt.encode(claims, payload.private_pem, algorithm="RS256", headers=headers)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"assertion_encode_failed: {e}")

    return {"client_assertion": token, "aud": aud, "exp": claims["exp"]}

class DebugMintIn(BaseModel):
    username: str = "alice"
    client_id: str = "demo-spa"
    scope: str = "openid profile email offline_access"
    audience: str | None = "frontend-api"
    resource: str | None = "https://api.local/patients"
    include_refresh: bool = True

@debug.post("/mint")
async def debug_mint(payload: DebugMintIn, request: Request, x_debug_key: str | None = Header(None)):
    require_localhost(request)
    require_debug_key(x_debug_key)

    user = await col_users.find_one({"username": payload.username})
    if not user:
        raise HTTPException(404, "user_not_found")

    client = await col_clients.find_one({"client_id": payload.client_id})
    if not client:
        raise HTTPException(404, "client_not_found")

    # enforce same validation rules as real flow
    validate_scopes(client, payload.scope)
    validate_audience_resource(client, payload.audience, payload.resource)

    access_token, expires_in = await mint_access_token(
        sub=user["sub"],
        client_id=payload.client_id,
        scope=payload.scope,
        audience=payload.audience,
        resource=payload.resource,
    )

    out = {
        "token_type": "Bearer",
        "access_token": access_token,
        "expires_in": expires_in,
        "scope": payload.scope,
    }

    if payload.include_refresh and "offline_access" in scopes_set(payload.scope):
        out["refresh_token"] = await mint_refresh_token(user["sub"], payload.client_id, payload.scope)

    return out

class DebugResetIn(BaseModel):
    confirm: str
    preserve_seed: bool = True  # keep users/clients/keys
    preserve_keys: bool = True

@debug.post("/reset")
async def debug_reset(payload: DebugResetIn, request: Request, x_debug_key: str | None = Header(None)):
    require_localhost(request)
    require_debug_key(x_debug_key)

    if payload.confirm != "RESET":
        raise HTTPException(400, "confirm_must_equal_RESET")

    # volatile
    await col_sessions.delete_many({})
    await col_csrf.delete_many({})
    await col_pending.delete_many({})
    await col_codes.delete_many({})
    await col_refresh.delete_many({})
    await col_access_opaque.delete_many({})
    await col_jti.delete_many({})

    if not payload.preserve_seed:
        await col_users.delete_many({})
        await col_clients.delete_many({})

    if not payload.preserve_keys:
        await col_keys.delete_many({})

    # re-seed if you wiped
    if not payload.preserve_seed or not payload.preserve_keys:
        await seed_if_empty()

    return {"reset": True, "preserve_seed": payload.preserve_seed, "preserve_keys": payload.preserve_keys}



if ENABLE_DEBUG_ENDPOINTS:
    app.include_router(debug)

async def claims_for_target(sub: str, scope: str, target: str, client: dict) -> dict:
    scope_set = scopes_set(scope)

    # 1) Expand scopes -> claim list for this target
    claim_names = set()
    async for sdef in col_scopes.find({"scope": {"$in": list(scope_set)}, "enabled": True}):
        if target in sdef.get("targets", []):
            claim_names.update(sdef.get("include_claims", []))

    # Always include sub for OIDC-ish things
    claim_names.add("sub")

    # 2) Client policy gating (optional)
    allowed_claims = set(client.get("allowed_claims", [])) or None
    if allowed_claims is not None:
        claim_names = {c for c in claim_names if c in allowed_claims or c == "sub"}

    # 3) Load user
    user = await col_users.find_one({"sub": sub})
    if not user:
        raise HTTPException(401, "unknown_sub")

    # 4) Resolve claims
    out = {"sub": sub}
    defs = col_claims.find({"claim": {"$in": list(claim_names)}})
    async for cdef in defs:
        claim = cdef["claim"]
        val = resolve_source(user, cdef.get("source"), default=cdef.get("default"))
        out[claim] = val

    return out

