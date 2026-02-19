##

References

https://medium.com/@devripper133127/setting-up-openldap-and-phpldapadmin-with-docker-compose-cf2336590989
https://github.com/osixia/docker-openldap/blob/master/image/service/slapd/assets/config/bootstrap/ldif/custom/README.md

Below is a **minimal, repeatable “directory-lab” baseline**: an LDAP directory server + a web-based admin UI, both in Docker. This is the quickest way to start experimenting with bind/search/modify/schema without bringing in heavier IAM stacks.

I’m using the very common **osixia/openldap** + **osixia/phpldapadmin** pairing (the phpLDAPadmin image is explicitly designed to point at an LDAP host via env vars). ([GitHub][1])

---

## 1) `docker-compose.yml`

Create a folder (e.g. `directory-lab/`) and add this file:

```yaml
services:
  openldap:
    image: osixia/openldap:latest
    container_name: directory-lab-openldap
    environment:
      LDAP_ORGANISATION: "Directory Lab"
      LDAP_DOMAIN: "example.org"
      LDAP_ADMIN_PASSWORD: "adminpassword"
      # Optional: enable verbose logs while learning
      LDAP_LOG_LEVEL: "256"
    ports:
      - "389:389"   # LDAP
      - "636:636"   # LDAPS
    volumes:
      - openldap_data:/var/lib/ldap
      - openldap_config:/etc/ldap/slapd.d
      # Drop LDIF files in ./ldif to auto-seed at first start
      - ./ldif:/container/service/slapd/assets/config/bootstrap/ldif/custom:ro
    restart: unless-stopped

  phpldapadmin:
    image: osixia/phpldapadmin:latest
    container_name: directory-lab-phpldapadmin
    environment:
      PHPLDAPADMIN_LDAP_HOSTS: "openldap"
      PHPLDAPADMIN_HTTPS: "false"  # keep simple for local lab
    ports:
      - "18081:80"
    depends_on:
      - openldap
    restart: unless-stopped

volumes:
  openldap_data:
  openldap_config:
```

This layout mirrors the upstream “openldap + phpldapadmin” compose example and the phpLDAPadmin env-var configuration approach. ([GitHub][1])

---

## 2) Start it

```bash
docker compose up -d
docker compose ps
```

You should now have:

* LDAP on **localhost:389**
* phpLDAPadmin on **[http://localhost:18081](http://localhost:18081)**

---

## 3) Login details (phpLDAPadmin)

In phpLDAPadmin:

* **Login DN**: `cn=admin,dc=example,dc=org`
* **Password**: `adminpassword`

Base DN is derived from `LDAP_DOMAIN=example.org` → `dc=example,dc=org`.

---

## 4) Seed some entries (optional but recommended)

Create a folder `ldif/` next to your compose file and add `ldif/01-bootstrap.ldif`:

```ldif
# admin user
dn: cn=admin,dc=example,dc=org
changetype: add
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: admin
userPassword: adminpassword
description: LDAP Administrator

# organisational unit for IT department
dn: ou=IT,dc=example,dc=org
changetype: add
objectClass: organizationalUnit
ou: IT

# user: John Doe for unit IT department
dn: uid=johndoe,ou=IT,dc=example,dc=org
changetype: add
objectClass: inetOrgPerson
cn: John Doe
sn: Doe
uid: johndoe
mail: johndoe@example.org
userPassword: password123
```

Then recreate once (seeding happens on first init):

```bash
docker compose down -v
docker compose up -d
```

---

## 5) Quick CLI verification (bind + search)

If you have `ldapsearch` locally:

```bash
ldapsearch -x \
  -H ldap://localhost:389 \
  -D "cn=admin,dc=example,dc=org" \
  -w adminpassword \
  -b "dc=example,dc=org" "(objectClass=*)"
```

Or run it inside the container (no local tooling needed):

```bash
docker exec -it directory-lab-openldap bash -lc \
'ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=org" -w adminpassword -b "dc=example,dc=org" "(objectClass=*)"'
```

---

## 6) Notes

* **Persistence**: you get durable storage via the named volumes (`openldap_data`, `openldap_config`). Blow them away with `docker compose down -v` when you want a clean slate.
* **Observability**: crank up `LDAP_LOG_LEVEL` to learn what ops look like server-side (you’ll see binds/searches/modifies in logs).
* **LDAPS**: it’s exposed on 636, but I’d keep most early experiments on plain LDAP for clarity, then add TLS once you’re comfortable with the protocol.

[1]: https://github.com/osixia/docker-openldap/blob/master/example/docker-compose.yml?utm_source=chatgpt.com "docker-openldap/example/docker-compose.yml at master"

# LDAP Schemas

For “a new user in LDAP”, you can ignore ~90% of this schema dump (config, replication, overlays, DNS, Samba, mail, etc.). The pieces that matter are the **person/user entry structural classes**, plus the **auxiliary classes you optionally add** (login, POSIX, SSH keys, etc.), and then **group classes** for authorisation.

## The objectClasses that matter for a user entry

### 1) The core person hierarchy (this is the “human” model)

This is the main inheritance chain you’ll almost always use:

```
top (ABSTRACT)
  └─ person (STRUCTURAL)  MUST: sn, cn
       └─ organizationalPerson (STRUCTURAL)  MAY: title, ou, l, st, etc.
            └─ inetOrgPerson (STRUCTURAL)  MAY: mail, uid, givenName, displayName, mobile, manager, etc.
```

**Why this is the core**

* `person` is the first *real* “human” structural class here. It enforces the minimum naming attributes: **cn + sn**.
* `organizationalPerson` adds common org attributes (department-ish fields, address/phone bits).
* `inetOrgPerson` is the modern “directory user” class used by most apps and IdPs (email, uid, givenName, displayName, etc.).

**In practice, a typical user entry uses:**

* `objectClass: top`
* `objectClass: person`
* `objectClass: organizationalPerson`
* `objectClass: inetOrgPerson`

…and then you populate attributes like:

* required: `cn`, `sn`
* very common: `givenName`, `uid`, `mail`, `displayName`, `telephoneNumber` / `mobile`
* optional org-ish: `ou`, `title`, `manager`

---

### 2) Login / credential-related auxiliaries (optional, depends on your server + auth model)

#### `simpleSecurityObject` (AUXILIARY) — password required if you use it

* **MUST:** `userPassword`
* Use this if you want to ensure a password is present (some deployments just allow `userPassword` via the structural class may-attributes; this makes it mandatory).

#### `pwdPolicy` / `pwdPolicyChecker` (AUXILIARY) — password policy *objects*, not “the user”

* `pwdPolicy` has **MUST:** `pwdAttribute` and then lots of policy knobs.
* Usually this is applied as a policy entry and referenced/attached depending on server features; it’s not “the basic user schema”.

---

### 3) Identity / username auxiliaries (optional)

#### `uidObject` (AUXILIARY)

* **MUST:** `uid`
* Useful if you want to enforce that a login name exists (because `inetOrgPerson` only lists `uid` as MAY).

---

### 4) Unix / POSIX login (optional, only if you need OS-level identities)

#### `posixAccount` (AUXILIARY)

* **MUST:** `cn`, `uid`, `uidNumber`, `gidNumber`, `homeDirectory`
* This turns your directory user into a Unix account for NSS/PAM integration, file permissions, etc.

#### `shadowAccount` (AUXILIARY)

* **MUST:** `uid`
* Adds shadow password aging fields (again, only for Unix-style logins).

---

### 5) SSH public keys (optional)

#### `ldapPublicKey` (AUXILIARY)

* **MAY:** `sshPublicKey`, `uid`
* Useful if you store SSH keys in LDAP for fleet/user provisioning.

---

## Group / authorisation objectClasses that relate to users

User entries don’t “contain” groups; groups contain user DNs (or usernames), and *that relationship* is how access control is typically modelled.

### A) DN-based groups (recommended when possible)

#### `groupOfNames` (STRUCTURAL)

* **MUST:** `cn`, `member` (member values are **DNs**)
* Great for “groups contain user DNs”.

#### `groupOfUniqueNames` (STRUCTURAL)

* **MUST:** `cn`, `uniqueMember`
* Similar, but uses `uniqueMember` (uniqueMember values are a DN plus optional UID component).

### B) Username-based groups (mostly for POSIX)

#### `posixGroup` (STRUCTURAL)

* **MUST:** `cn`, `gidNumber`
* **MAY:** `memberUid` (memberUid values are **strings** like usernames, not DNs)

---

## How they relate (putting it all together)

### Typical “directory user” (apps / SSO / IAM)

* Structural chain: `inetOrgPerson → organizationalPerson → person → top`
* Optionally enforce username/password:

  * add `uidObject` to force `uid`
  * add `simpleSecurityObject` to force `userPassword`
* Authorisation via groups:

  * put the user’s DN into `groupOfNames.member` (or `groupOfUniqueNames.uniqueMember`)

### Typical “Unix + LDAP” user (servers, SSH, home dirs)

* Same `inetOrgPerson` chain **plus**
* `posixAccount` (+ often `shadowAccount`)
* Groups:

  * `posixGroup` with `memberUid: <uid>` and matching `gidNumber`

---

## Minimal examples (based on *your* schema)

### 1) Minimal app user (most common)

**objectClasses**

* `top`
* `person`
* `organizationalPerson`
* `inetOrgPerson`

**minimum attributes**

* `cn`, `sn`

**recommended**

* `uid`, `mail`, `givenName`, `displayName`

### 2) Group referencing that user

**groupOfNames**

* `objectClass: top`
* `objectClass: groupOfNames`
* `cn: some-role`
* `member: uid=martin,ou=people,dc=example,dc=com` (user DN)

---
# Lab endpoints

Below is **copy/paste-ready Markdown** documenting each endpoint in the snippet: what it does, how it’s wired, and how to call it with `curl`.

---

# Directory Lab API

Base URL (local): `http://localhost:3001`

## Common concepts

### Connection inputs

Most endpoints accept connection settings either via **query params** (GETs) or **JSON body** (POST/PATCH):

* `ldapUrl` — LDAP endpoint, e.g. `ldap://localhost:389` or `ldaps://localhost:636`
* `bindDn` / `bindPassword` — credentials used to bind (authenticate) the LDAP client
* `baseDn` — the directory suffix / naming context, e.g. `dc=example,dc=org`
* `startTls` — if `true`, attempt StartTLS on `ldap://` connections *(will fail if server doesn’t support it)*

Defaults in code (lab):

* `LDAP_URL = ldap://localhost:389`
* `LDAP_BIND_DN = cn=admin,dc=example,dc=org`
* `LDAP_BIND_PASSWORD = adminpassword`

### Errors

Most endpoints return:

* `400` for missing required inputs
* `401` for failed authentication in `/directory/auth/test`
* `502` for LDAP/network errors or server-side failures

---

# GET /directory/info

## Purpose

Fetch high-level directory server info (Root DSE / introspection), such as naming contexts and supported controls/extensions.

## What the code does

* Reads `ldapUrl`, and optional `bindDn` / `bindPassword` from query params (fallback to defaults).
* Calls `utils.fetchDirectoryInfo(ldapUrl, bindDn?, bindPassword?)`.
* Returns the info object as JSON.

## Query parameters

* `ldapUrl` *(optional)*
* `bindDn` *(optional)*
* `bindPassword` *(optional)*

## Example

```bash
curl -s "http://localhost:3001/directory/info?ldapUrl=ldap://localhost:389&bindDn=cn=admin,dc=example,dc=org&bindPassword=adminpassword" | jq .
```

---

# GET /directory/capabilities

## Purpose

Return directory introspection + “human-friendly” capability descriptions for controls, extensions, and features.

## What the code does

* Fetches the same base info as `/directory/info`.
* Enhances it with:

  * `controls`: `utils.describeOids(info.supportedControls, "control")`
  * `extensions`: `utils.describeOids(info.supportedExtensions, "extension")`
  * `features`: from `raw.supportedFeatures` if present
* Returns the enriched JSON.

## Query parameters

* `ldapUrl` *(optional)*
* `bindDn` *(optional)*
* `bindPassword` *(optional)*

## Example

```bash
curl -s "http://localhost:3001/directory/capabilities?ldapUrl=ldap://localhost:389" | jq .
```

---

# GET /directory/whoami

## Purpose

Execute the LDAP **Who Am I?** extended operation to confirm the *authorization identity* of the current bind.

## What the code does

1. Calls `utils.fetchDirectoryInfo(...)` to check if the server advertises WhoAmI support (`1.3.6.1.4.1.4203.1.11.3`).
2. Requires `bindDn` + `bindPassword`.
3. Binds using `ldapts` `Client`.
4. Calls `client.exop(WHOAMI_OID)` and returns `authzId`.

## Query parameters

* `ldapUrl` *(optional)*
* `bindDn` *(required)*
* `bindPassword` *(required)*

## Examples

**Successful WhoAmI**

```bash
curl -s "http://localhost:3001/directory/whoami?ldapUrl=ldap://localhost:389&bindDn=cn=admin,dc=example,dc=org&bindPassword=adminpassword" | jq .
```

**Server does not support WhoAmI (returns 501)**

```bash
curl -s "http://localhost:3001/directory/whoami?ldapUrl=ldap://some-server:389&bindDn=cn=admin,dc=example,dc=org&bindPassword=adminpassword" | jq .
```

---

# POST /directory/auth/test

## Purpose

“Smoke test” credentials by performing a bind, and optionally WhoAmI if supported.

## What the code does

* Reads JSON body: `ldapUrl` (optional), `bindDn`, `bindPassword`.
* Validates required credentials.
* Binds using `ldapts` `Client`.
* Fetches directory info to check WhoAmI support.
* If supported: calls WhoAmI and returns `authzId`.

## Request body

```json
{
  "ldapUrl": "ldap://localhost:389",
  "bindDn": "cn=admin,dc=example,dc=org",
  "bindPassword": "adminpassword"
}
```

## Example

```bash
curl -s -X POST "http://localhost:3001/directory/auth/test" \
  -H "content-type: application/json" \
  -d '{
    "ldapUrl": "ldap://localhost:389",
    "bindDn": "cn=admin,dc=example,dc=org",
    "bindPassword": "adminpassword"
  }' | jq .
```

---

# POST /directory/search

## Purpose

Generic LDAP search endpoint with guardrails (size/time limits and attribute sanitization).

## What the code does

* Reads connection config + search config from JSON.
* Requires `baseDn` and `filter`.
* Applies guardrails:

  * `sizeLimit` clamped to `[1..200]` (default 50)
  * `timeLimitSeconds` clamped to `[1..15]` (default 5)
  * `attributes` sanitized to block sensitive ones (`userPassword`, `olcRootPW`)
* Creates `ldapts` `Client`, binds with service credentials, performs `client.search(...)`.
* Returns `entries` from `result.searchEntries` plus timing.

## Request body

```json
{
  "ldapUrl": "ldap://localhost:389",
  "bindDn": "cn=admin,dc=example,dc=org",
  "bindPassword": "adminpassword",
  "baseDn": "dc=example,dc=org",
  "scope": "sub",
  "filter": "(objectClass=*)",
  "attributes": ["dn","objectClass","cn","sn","uid","mail"],
  "sizeLimit": 50,
  "timeLimitSeconds": 5
}
```

## Example

```bash
curl -s "http://localhost:3001/directory/search" \
  -H "content-type: application/json" \
  -d '{
    "baseDn": "dc=example,dc=org",
    "scope": "sub",
    "filter": "(objectClass=*)",
    "attributes": ["dn","objectClass","cn","sn","uid","mail"],
    "sizeLimit": 50
  }' | jq .
```

---

# POST /directory/auth/test2

## Purpose

Same general goal as `/directory/auth/test`, but uses your **DirectoryClient wrapper** to support:

* `ldap://` plain
* `ldap://` + StartTLS
* (optionally) relaxed TLS verification or custom CA PEM

## What the code does

* Reads JSON body `AuthTestBody`.
* Builds optional `tlsOptions` if `allowInsecureTLS` or `caCertPem` is provided (note: in this snippet, `tlsOptions` is computed but not passed into `DirectoryClient`; if your `DirectoryClient` supports it, wire it in).
* Creates a `DirectoryConnectionConfig` and calls:

  * `client.connectAndBind()`
* Returns `{ ok: true, ldapUrl, bindDn, startTls }` on success.

## Request body

```json
{
  "ldapUrl": "ldap://localhost:389",
  "startTls": false,
  "bindDn": "cn=admin,dc=example,dc=org",
  "bindPassword": "adminpassword",
  "allowInsecureTLS": false,
  "caCertPem": null
}
```

## Examples

**Plain LDAP bind**

```bash
curl -s -X POST "http://localhost:3001/directory/auth/test2" \
  -H "content-type: application/json" \
  -d '{
    "ldapUrl":"ldap://localhost:389",
    "startTls": false,
    "bindDn":"cn=admin,dc=example,dc=org",
    "bindPassword":"adminpassword"
  }' | jq .
```

**StartTLS bind (requires server support)**

```bash
curl -s -X POST "http://localhost:3001/directory/auth/test2" \
  -H "content-type: application/json" \
  -d '{
    "ldapUrl":"ldap://localhost:389",
    "startTls": true,
    "bindDn":"cn=admin,dc=example,dc=org",
    "bindPassword":"adminpassword"
  }' | jq .
```

---

# GET /directory/base-dn/validate

## Purpose

Verify that a configured `baseDn`:

* exists, and
* is searchable (returns at least one entry at scope `base`)

## What the code does

* Reads:

  * `ldapUrl` (optional)
  * `baseDn` (**required**)
  * bind creds (optional; defaults used)
  * `startTls` and `allowInsecureTLS` flags (lab)
* Uses `DirectoryClient.connectAndBind()`
* Executes a base search:

  * `scope: "base"`
  * `filter: "(objectClass=*)"`
  * `attributes: ["dn", "objectClass"]`
  * `sizeLimit: 1`
* If no entries returned: 404 `BASE_DN_NOT_FOUND`
* Otherwise returns `{ ok: true, sample: firstEntry }`

## Query parameters

* `baseDn` *(required)*
* `ldapUrl` *(optional)*
* `bindDn` *(optional)*
* `bindPassword` *(optional)*
* `startTls` *(optional, "true"|"false")*
* `allowInsecureTLS` *(optional, "true"|"false")*

## Examples

**Minimal (just baseDn)**

```bash
curl -s "http://localhost:3001/directory/base-dn/validate?baseDn=dc=example,dc=org" | jq .
```

**With explicit connection details**

```bash
curl -s "http://localhost:3001/directory/base-dn/validate?ldapUrl=ldap://localhost:389&baseDn=dc=example,dc=org&startTls=false" | jq .
```

---

# GET /directory/schema

## Purpose

Fetch a summary of schema (objectClasses + attributeTypes), optionally filtered by a substring query.

## What the code does

* Reads connection details from query.
* Reads `q` from query, lowercases and trims.
* Calls `utils.fetchSchemaSummary(ldapUrl, bindDn?, bindPassword?)`.
* If `q` is provided, filters:

  * `objectClasses` by name includes `q`
  * `attributeTypes` by name includes `q`

## Query parameters

* `ldapUrl` *(optional)*
* `bindDn` *(optional)*
* `bindPassword` *(optional)*
* `q` *(optional)*

## Examples

**Fetch full schema summary**

```bash
curl -s "http://localhost:3001/directory/schema?ldapUrl=ldap://localhost:389" | jq .
```

**Filter schema by substring**

```bash
curl -s "http://localhost:3001/directory/schema?q=person" | jq .
```

---

# People endpoints

These endpoints implement CRUD over `inetOrgPerson` entries located under:

* People container DN: `ou=People,<baseDn>`
* Person DN convention: `uid=<uid>,ou=People,<baseDn>` (via `user.peopleDn(uid, baseDn)`)

They all use `DirectoryClient` with:

* `ldapUrl`
* `bindDn` / `bindPassword`
* `startTls`

## GET /directory/people

### Purpose

List/search people in `ou=People,<baseDn>`. Supports query-based search across common attributes.

### What the code does

* Reads:

  * `q` (search term)
  * `limit` (clamped to `[1..MAX_LIMIT]`)
  * LDAP connection params from query
* Builds an LDAP filter:

  * If `q` present: `(&(objectClass=inetOrgPerson)(|(uid=*q*)(cn=*q*)(sn=*q*)(mail=*q*)))`
  * Else: `(objectClass=inetOrgPerson)`
* Searches under `ou=People,<baseDn>`, scope `sub`
* Maps entries via `user.mapPerson`

### Query parameters

* `q` *(optional)*
* `limit` *(optional)*
* `ldapUrl` *(optional)*
* `bindDn` *(optional)*
* `bindPassword` *(optional)*
* `baseDn` *(optional; default dc=example,dc=org)*
* `startTls` *(optional)*

### Examples

**List all people**

```bash
curl -s "http://localhost:3001/directory/people?baseDn=dc=example,dc=org" | jq .
```

**Search**

```bash
curl -s "http://localhost:3001/directory/people?baseDn=dc=example,dc=org&q=john&limit=10" | jq .
```

---

## GET /directory/people/:uid

### Purpose

Fetch a single person by `uid`.

### What the code does

* Builds DN: `uid=<uid>,ou=People,<baseDn>`
* Performs a base search on that DN.
* Returns `404` if not found.

### Query parameters

* `baseDn` *(optional; default dc=example,dc=org)*
* `ldapUrl`, `bindDn`, `bindPassword`, `startTls` *(optional)*

### Example

```bash
curl -s "http://localhost:3001/directory/people/johndoe?baseDn=dc=example,dc=org" | jq .
```

---

## POST /directory/people

### Purpose

Create a new `inetOrgPerson` under `ou=People,<baseDn>`.

### What the code does

* Reads JSON body including `uid`, `cn`, `sn` (+ optional `mail`, `password`)
* Requires: `baseDn`, `uid`, `cn`, `sn`
* Adds entry with objectClasses:

  * `top`, `person`, `organizationalPerson`, `inetOrgPerson`
* Optionally sets `userPassword` if `password` is provided

### Request body (example)

```json
{
  "baseDn": "dc=example,dc=org",
  "uid": "alice",
  "cn": "Alice Example",
  "sn": "Example",
  "mail": "alice@example.org",
  "password": "Passw0rd!",
  "ldapUrl": "ldap://localhost:389",
  "startTls": false,
  "bindDn": "cn=admin,dc=example,dc=org",
  "bindPassword": "adminpassword"
}
```

### Example

```bash
curl -s -X POST "http://localhost:3001/directory/people" \
  -H "content-type: application/json" \
  -d '{
    "baseDn":"dc=example,dc=org",
    "uid":"alice",
    "cn":"Alice Example",
    "sn":"Example",
    "mail":"alice@example.org",
    "password":"Passw0rd!",
    "ldapUrl":"ldap://localhost:389",
    "startTls": false,
    "bindDn":"cn=admin,dc=example,dc=org",
    "bindPassword":"adminpassword"
  }' | jq .
```

---

## PATCH /directory/people/:uid

### Purpose

Update selected attributes for a person.

### What the code does

* Requires `baseDn` and `uid`
* Builds a list of LDAP modify operations using `replace(...)`:

  * `cn`, `sn`
  * `mail` can be **cleared** by sending `mail: null` (replaces with empty array)
  * `password` sets `userPassword`
* Rejects if no fields supplied.

### Request body (example)

```json
{
  "baseDn": "dc=example,dc=org",
  "cn": "Alice Updated",
  "mail": null,
  "ldapUrl": "ldap://localhost:389",
  "startTls": false,
  "bindDn": "cn=admin,dc=example,dc=org",
  "bindPassword": "adminpassword"
}
```

### Example

```bash
curl -s -X PATCH "http://localhost:3001/directory/people/alice" \
  -H "content-type: application/json" \
  -d '{
    "baseDn":"dc=example,dc=org",
    "cn":"Alice Updated",
    "mail": null,
    "ldapUrl":"ldap://localhost:389",
    "startTls": false,
    "bindDn":"cn=admin,dc=example,dc=org",
    "bindPassword":"adminpassword"
  }' | jq .
```

---

## DELETE /directory/people/:uid

### Purpose

Delete a person entry.

### What the code does

* Builds DN: `uid=<uid>,ou=People,<baseDn>`
* Calls `client.del(dn)` and returns `{ ok: true, dn, uid }` on success.

### Query parameters

* `baseDn` *(optional; default dc=example,dc=org)*
* `ldapUrl`, `bindDn`, `bindPassword`, `startTls` *(optional)*

### Example

```bash
curl -s -X DELETE "http://localhost:3001/directory/people/alice?baseDn=dc=example,dc=org&ldapUrl=ldap://localhost:389&startTls=false&bindDn=cn=admin,dc=example,dc=org&bindPassword=adminpassword" | jq .
```
---
