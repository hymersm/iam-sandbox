# OIDC / OAuth2 Server (FastAPI + MongoDB)

A self-contained OpenID Connect (OIDC) and OAuth 2.0 authorization server implemented in FastAPI, backed by MongoDB.

This project models the core behaviour of a modern Identity Provider (IdP) and Authorization Server, including:

* OIDC Authorization Code + PKCE
* JWT or opaque access tokens
* Refresh token rotation with reuse detection
* Token introspection (RFC 7662)
* Token revocation (RFC 7009)
* Token exchange (RFC 8693)
* `private_key_jwt` client authentication (RFC 7523)
* JWKS publishing and signing key rotation

The goal of this implementation is to behave like a credible, standards-aligned OIDC provider while remaining understandable and extensible.

---

# Architecture Overview

```
┌──────────────┐
│ Browser / SPA│
└──────┬───────┘
       │ Authorization Code + PKCE
       ▼
┌────────────────────────┐
│ FastAPI OIDC Provider  │
│  - /authorize          │
│  - /token              │
│  - /userinfo           │
│  - /introspect         │
│  - /revoke             │
│  - /.well-known        │
│  - /jwks               │
└──────────┬─────────────┘
           │
           ▼
     MongoDB (state)
```

The server maintains state for:

* Users
* OAuth clients
* Sessions
* Authorization codes
* Refresh tokens (with rotation family tracking)
* Opaque access tokens (if enabled)
* JWT denylist entries
* Signing keys

---

# Supported Standards

| Standard                       | Status |
| ------------------------------ | ------ |
| OAuth 2.0 Authorization Code   | ✅      |
| PKCE (RFC 7636)                | ✅      |
| OIDC Core (basic)              | ✅      |
| JWT Access Tokens              | ✅      |
| Opaque Access Tokens           | ✅      |
| Refresh Token Rotation         | ✅      |
| Token Introspection (RFC 7662) | ✅      |
| Token Revocation (RFC 7009)    | ✅      |
| Token Exchange (RFC 8693)      | ✅      |
| private_key_jwt (RFC 7523)     | ✅      |
| JWKS Publishing                | ✅      |
| Key Rotation                   | ✅      |

---

# Configuration

Environment variables:

```
ISSUER=http://localhost:8000
MONGO_URL=mongodb://localhost:27017
MONGO_DB=oidc

ACCESS_TOKEN_MODE=jwt   # jwt | opaque

ACCESS_TTL_SECONDS=600
ID_TTL_SECONDS=600
AUTH_CODE_TTL_SECONDS=120
CSRF_TTL_SECONDS=600

COOKIE_SECURE=false
ENABLE_DEBUG_ENDPOINTS=false
DEBUG_KEY=<required if debug enabled>
```

---

# Default Seeded Data

### Users

* alice / password
* bob / password

### Clients

| Client ID           | Type         | Auth Method         | Notes                   |
| ------------------- | ------------ | ------------------- | ----------------------- |
| demo-spa            | public       | none                | PKCE required           |
| demo-backend-secret | confidential | client_secret_basic | Supports token exchange |
| demo-backend-pkjwt  | confidential | private_key_jwt     | Supports token exchange |

---

# Core Workflows

---

## 1. Authorization Code + PKCE (SPA)

### Step 1 — Redirect to `/oauth2/authorize`

```
GET /oauth2/authorize
  ?response_type=code
  &client_id=demo-spa
  &redirect_uri=http://localhost:5173/callback
  &scope=openid profile email
  &state=abc123
  &nonce=xyz789
  &code_challenge=<S256>
  &code_challenge_method=S256
```

Server:

* Validates client + redirect URI
* Requires login
* Requires consent
* Stores pending consent
* Issues authorization code

---

### Step 2 — Exchange Code

```
POST /oauth2/token
grant_type=authorization_code
code=...
redirect_uri=...
code_verifier=...
client_id=demo-spa
```

Returns:

```json
{
  "access_token": "...",
  "id_token": "...",
  "refresh_token": "...",
  "expires_in": 600,
  "token_type": "Bearer"
}
```

---

## 2. Refresh Token Rotation

When exchanging:

```
grant_type=refresh_token
refresh_token=rt_id.rt_secret
```

Server:

* Verifies client ownership
* Detects reuse attempts
* Rotates refresh token
* Revokes family on replay

This implements production-grade refresh rotation semantics.

---

## 3. private_key_jwt Client Authentication

Confidential clients can authenticate with signed JWT assertions:

```
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=<signed JWT>
```

Server:

* Loads client JWK
* Verifies signature
* Verifies:

  * iss == client_id
  * sub == client_id
  * aud == token endpoint
  * exp/iat present

This matches RFC 7523 behaviour.

---

## 4. Token Introspection

```
POST /oauth2/introspect
token=<access_token>
client authentication required
```

Opaque mode:

* Looks up token in DB

JWT mode:

* Verifies signature
* Checks denylist
* Returns full claim set

Example response:

```json
{
  "active": true,
  "sub": "user-alice-001",
  "client_id": "demo-spa",
  "scope": "openid profile email",
  "aud": "frontend-api",
  "exp": 1771515184
}
```

Only confidential clients may introspect.

---

## 5. Token Revocation

```
POST /oauth2/revoke
token=<refresh or access token>
```

Refresh token:

* Revokes entire family

Opaque access token:

* Marks revoked

JWT access token:

* Inserts jti into denylist

---

## 6. Token Exchange (RFC 8693)

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=...
scope=...
```

Server:

* Validates subject token
* Enforces downscoping
* Optionally includes actor claim
* Issues new access token

Supports service-to-service delegation patterns.

---

# Access Token Modes

## JWT Mode (default)

* Self-contained
* Signed with RS256
* Published via JWKS
* Revocable via denylist

Best for distributed systems.

## Opaque Mode

* Stored in Mongo
* Requires introspection
* Easier immediate revocation

Best for strict revocation control.

---

# Security Characteristics

Implemented:

* PKCE required for public clients
* Nonce required for OIDC
* CSRF protection on login + consent
* Refresh token reuse detection
* Session fixation protection
* Security headers
* Rate limiting (basic in-memory)
* Signing key rotation
* JTI denylist support

---

# What Makes This a Credible OIDC Provider

This server:

* Enforces redirect URI validation
* Enforces scope allowlists
* Enforces audience/resource allowlists
* Implements client authentication modes correctly
* Supports key rotation via JWKS
* Rotates refresh tokens securely
* Detects refresh token replay
* Separates opaque vs JWT access strategies
* Implements token exchange correctly with downscoping
* Protects introspection to confidential clients

The behaviour aligns closely with enterprise IAM products such as:

* ForgeRock / Ping
* Auth0
* Keycloak
* Azure AD (conceptually)

---

# Intended Usage Patterns

This server can act as:

### 1. SPA Identity Provider

* Authorization Code + PKCE
* JWT access tokens
* UserInfo endpoint

### 2. Backend-to-Backend Authorization Server

* client_secret_basic or private_key_jwt
* Token exchange
* Audience-restricted access tokens

### 3. API Gateway Validation Authority

* JWKS publishing
* JWT validation
* Introspection endpoint

### 4. Delegation Broker

* Token exchange
* Actor claims

---

# Development & Debug Utilities

When `ENABLE_DEBUG_ENDPOINTS=true`:

* `/debug/pkce`
* `/debug/jwt/decode`
* `/debug/mint`
* `/debug/reset`
* `/debug/client-assertion`

These are for development only and should not be enabled in production.

---

# Production Considerations

This project models a real OIDC provider, but production hardening requires:

* Admin endpoint authentication
* Encrypted key storage (KMS)
* Distributed rate limiting
* Structured audit logging
* Audience enforcement policy for introspection
* Replay protection for client assertions
* Observability & metrics
* TLS termination
* Secure deployment model (k8s/Ingress/WAF)

---

# Roadmap Potential

* RP-initiated logout
* PAR (Pushed Authorization Requests)
* DPoP
* mTLS-bound tokens
* Fine-grained consent management
* Session-bound access tokens
* Dynamic client registration

---

# Summary

This implementation demonstrates:

* A standards-aligned OAuth 2.0 and OIDC server
* Modern best practices (PKCE, rotation, JWT, JWK)
* Enterprise IAM patterns (token exchange, introspection, revocation)
* Clear separation of concerns between browser flows and service flows

It provides a credible foundation for:

* Learning OIDC internals
* Security architecture experimentation
* Integration testing
* IAM design prototyping
* Demonstrating advanced OAuth capabilities in interviews or technical discussions

---

If you would like, I can also generate:

* An architecture diagram (SVG / Mermaid)
* A sequence diagram for each flow
* A conformance checklist
* A SOC2 control mapping for this service
