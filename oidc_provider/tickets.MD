Below is a **productionization backlog** for this FastAPI OIDC/OAuth2 server, prioritised by **security impact**, then **interop impact**, then **operability**. I’ve grouped items into epics and given each ticket a crisp **Definition of Done (DoD)**.

Assumptions: you want something that can credibly sit behind an ALB/Ingress in EKS, back Mongo (or swap later), and interoperate with common RPs/resource servers.

---

# Epic A — Admin security & blast-radius reduction (P0)

### A1. Add admin authentication + authorization

**Problem:** `/admin/*` is unauthenticated (production blocker).
**DoD:**

* All `/admin/*` routes require strong auth (choose one):

  * mTLS + network allowlist (recommended for lab-to-prod), or
  * OIDC admin login + RBAC role, or
  * signed admin JWT with rotation + allowlist.
* Explicit RBAC checks (e.g., `role=admin`, `perm=keys:rotate`, `perm=clients:update`).
* Deny by default.

### A2. Remove or compile-time disable `/debug/*` in prod builds

**DoD:**

* Debug router never enabled in production image (build arg or env + CI guard).
* Unit test asserts debug routes absent when `ENABLE_DEBUG_ENDPOINTS=false`.

### A3. Secrets hygiene for seeded clients

**Problem:** plaintext `client_secret` in DB.
**DoD:**

* Store `client_secret_hash` (Argon2 or bcrypt) instead of plaintext.
* Add secret rotation endpoint (admin) that issues a new secret and invalidates old.
* Documentation for secret rotation rollout.

---

# Epic B — Key management & JWKS correctness (P0)

### B1. Correct key rollover semantics

**Problem:** publishing only “active” keys can break validation after rotation.
**DoD:**

* Introduce key states:

  * `signing=true/false` (current signer)
  * `published=true/false` (in JWKS)
  * `retire_at` (timestamp when safe to stop publishing)
* Rotation keeps previous key **published** until `max(token_lifetime)` has elapsed.
* `/oauth2/jwks` returns all `published=true` keys.

### B2. Protect private keys at rest (KMS/HSM or encrypted envelope)

**DoD:**

* Private key material not stored in plaintext in Mongo.
* Use AWS KMS for envelope encryption (or at minimum libsodium/fernet with env key).
* Key decrypt occurs only in-process with least privilege.
* Add key backup/restore playbook.

### B3. Add signature verification before denylisting JWTs

**Problem:** `/oauth2/revoke` can insert arbitrary `jti` without verifying JWT signature.
**DoD:**

* When token looks like JWT, verify signature and `iss` before denylisting.
* Denylist entries include `(iss, jti, exp)` at minimum.

---

# Epic C — OAuth/OIDC correctness & interoperability (P0/P1)

### C1. Enforce strict `aud` checks where appropriate

**Problem:** `verify_aud=False` everywhere is risky.
**DoD:**

* For RS validation endpoints:

  * `/userinfo` verifies `aud` contains `userinfo`-accepted audience (or a configured value).
  * Introspection in JWT mode either:

    * verifies aud, **or**
    * enforces the introspection caller is authorized for the token’s audience/resource (see C2).
* Document audience strategy (single-aud vs multi-aud).

### C2. Introspection authorization policy (who may introspect which tokens)

**DoD:**

* Determine token target: `aud` and/or `resource`.
* Only allow introspection if introspection client is permitted for that target:

  * Add `introspect_allowed_audiences/resources` to client config **or**
  * Map resource server identities to audiences/resources.
* Add tests:

  * allowed client can introspect
  * disallowed client gets `403` (not `401`).

### C3. Standardize OAuth error responses

**DoD:**

* Errors returned as:

  ```json
  {"error":"invalid_grant","error_description":"...","error_uri":"...optional"}
  ```
* HTTP status codes align with common practice:

  * `invalid_client` → 401 with `WWW-Authenticate`
  * `invalid_grant` → 400
  * `insufficient_scope` → 403 etc.
* Add integration tests for major error cases.

### C4. OIDC ID Token claim completeness (baseline)

**DoD:**

* ID Token includes: `iss`, `sub`, `aud`, `iat`, `exp`, `nonce` (already), plus:

  * `auth_time` (if you want session age semantics)
  * `azp` when applicable
* Optionally add `amr` / `acr` scaffolding.
* Add OIDC conformance-style tests for ID token structure.

### C5. Add OIDC RP-initiated logout (end_session_endpoint)

**DoD:**

* Implement `/oauth2/logout` or `/logout`:

  * clears session cookie
  * supports `post_logout_redirect_uri` allowlist per client
  * supports `id_token_hint` validation (optional but typical)
* Publish `end_session_endpoint` in discovery.

---

# Epic D — Token & session lifecycle controls (P0/P1)

### D1. Access token TTL strategy (production defaults)

**DoD:**

* Default access token TTL ≤ 10 minutes (you have 600s — good).
* Refresh TTL per client and configurable.
* Policy to disallow refresh tokens for public clients unless explicitly enabled (right now SPA gets refresh via `offline_access`).

### D2. Bind refresh tokens to client + optional session/device

**DoD:**

* Refresh token records store `client_id` (already) and optionally:

  * `sid` (session id) or device id
  * `rotated_at`, `last_used_at`, `ip_hash`, `ua_hash` (optional)
* Optional policy: revoke refresh family when session ends.

### D3. Add `jti` replay detection for client assertions (private_key_jwt)

**Problem:** attacker can replay the same client assertion until `exp`.
**DoD:**

* Store used assertion `jti` for `(client_id, jti)` with TTL until `exp`.
* Reject reuse with `invalid_client`.
* Add tests.

### D4. Improve revocation semantics + clarity

**DoD:**

* Explicit `token_type_hint` support:

  * `refresh_token` → revoke family
  * `access_token` → revoke opaque or denylist JWT
* If hint absent, infer carefully (don’t treat “.” as refresh token when JWTs also contain dots).

  * For JWT: `token.count('.')==2`
  * For refresh: your current `rt_id.rt_secret` (one dot) is fine; be explicit.
* Return same response shape always (per RFC 7009), but ensure correct internal action.

---

# Epic E — Hardening: web security, abuse resistance (P0/P1)

### E1. Replace in-process rate limit with shared limiter

**DoD:**

* Use Redis-backed limiter or API Gateway/WAF.
* Per-endpoint and per-identity limits:

  * login: username + IP
  * token: client_id + IP
  * introspect/revoke: client_id + IP
* Add “burst + sustained” thresholds.

### E2. Add account lockout / credential stuffing protections

**DoD:**

* Track failed login attempts per username and per IP.
* Temporary lockouts with exponential backoff.
* Optional: CAPTCHA gate after threshold (if you want UI realism).

### E3. Cookie hardening

**DoD:**

* Configure cookie `Secure`, `HttpOnly`, `SameSite`, `Path`, optional `Domain`.
* Consider `SameSite=None; Secure` only if needed for cross-site usage.
* Add session rotation on privilege change (future-proof).

### E4. Security headers tuning for real OIDC pages

**DoD:**

* CSP updated to support your templates safely (avoid breaking login/consent assets).
* Consider `form-action` and `frame-ancestors` specifics.
* Add HSTS if served over TLS.

---

# Epic F — Observability & auditability (P0/P1)

### F1. Structured audit log events

**DoD:**

* Emit append-only audit events for:

  * login success/failure
  * consent allow/deny
  * token issuance (grant_type, client_id, sub, aud, scope, jti/opaque id)
  * refresh rotate/reuse detected
  * introspection calls (caller client_id, token target)
  * revocations
  * admin operations (rotate keys, set client jwk)
* Ensure logs redact secrets/tokens (log hashes or token ids only).

### F2. Metrics & tracing

**DoD:**

* Prometheus metrics for:

  * request counts/latency per endpoint
  * token issuance counts by grant_type
  * auth failures by reason
  * rate limit hits
* Correlation ID middleware (propagate `X-Request-Id`).

### F3. Operational timeouts & Mongo hardening

**DoD:**

* Configure Mongo client timeouts + retries appropriately.
* Add indexes:

  * `access_tokens_opaque.token` unique/index
  * `refresh_tokens.rt_id` unique/index
  * `auth_codes.code` unique/index
  * `sessions.sid` unique/index
* Add health check endpoint (non-debug) suitable for k8s readiness/liveness.

---

# Epic G — OIDC feature completeness (P1/P2, depending on goals)

### G1. Add `/oauth2/token` support for `client_secret_post` (optional)

**DoD:**

* Support if you need broader client compatibility (many libs support it).
* Keep disabled by default; enable per client.

### G2. Add OIDC `claims` parameter and consented claims (optional)

**DoD:**

* Parse `claims` request param and map to user attributes.
* Reflect consent into ID token and/or userinfo.

### G3. Add PAR (Pushed Authorization Requests) (optional but modern)

**DoD:**

* `/oauth2/par` endpoint for large/sensitive auth requests.
* `request_uri` support.

### G4. Add DPoP or mTLS sender-constrained tokens (advanced)

**DoD:**

* DPoP proof validation at token endpoint
* Bind access token to `cnf` claim
* RS verification guidance

---

# Suggested implementation order (fastest path to “credible production”)

**Week 1 / P0 core**

1. A1 admin auth + A2 remove debug in prod
2. B1 key rollover publishing correctness
3. C1 audience enforcement + C2 introspection authorization
4. D3 client assertion `jti` replay detection
5. E1 shared rate limiting
6. F1 audit logs (minimal)

**Week 2 / P1**
7. B2 key encryption (KMS)
8. D4 revocation inference improvements
9. C5 logout
10. F2 metrics/tracing + F3 health checks/indexes

---

# Quick call-outs: your biggest “gotchas” today

If you only fixed three things, fix these:

1. **Admin endpoints unauthenticated** (blocker)
2. **Key rollover/JWKS semantics** (will break clients)
3. **Audience/introspection authorization** (token forwarding + data exposure risk)

---

If you want this as a Jira-ready backlog, I can convert each ticket into:

* summary
* description
* acceptance criteria
* test plan
* estimated effort (S/M/L)
* SOC2 mapping (CC6/CC7 style)
  …in the same style you’ve used for your compliance epics.
