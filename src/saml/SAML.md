# SAML → Token Exchange Lab (PingAM-style IAM Exploration)

## Introduction

This repository is a **hands-on identity and access management (IAM) lab** designed to explore how **SAML-based authentication** integrates with **modern token-based application architectures**.

The lab intentionally starts with **classic enterprise SAML** (SP ↔ IdP browser SSO) and progressively bridges into:

* application sessions
* JWT issuance
* token exchange / delegation
* microservice-oriented authorization patterns

The goal is not to “build an IdP”, but to **understand the trust boundaries, protocol responsibilities, and transformation points** that exist between legacy federation (SAML) and contemporary API security models (OAuth2 / JWT).

---

## Technologies used

This lab deliberately combines **old-world enterprise IAM** with **modern application patterns**.

### Identity & Federation

* **SAML 2.0**

  * SP-initiated browser SSO
  * Signed assertions
  * Metadata-driven trust
* **SimpleSAMLphp (Docker)**

  * Used as a lightweight IdP for local development
  * Represents enterprise IdPs such as PingAM, PingFederate, ADFS, etc.

### Service Provider (SP)

* **Node.js + TypeScript**
* **Express**
* **Passport.js**
* **@node-saml/passport-saml**

  * SAML protocol handling
  * Assertion validation
  * Profile normalisation
* **express-session**

  * Post-SAML session handling

### Token & API Layer

* **JWT (JSON Web Tokens)**

  * Application access tokens
  * Down-scoped service tokens
* **Bearer token validation**
* **Token exchange emulation**

  * Inspired by OAuth 2.0 Token Exchange (RFC 8693)

---

## Why this lab exists

This lab was created to answer practical, architectural questions such as:

* How does **SAML actually work end-to-end**, beyond “magic redirects”?
* Where does **authentication end** and **authorization begin**?
* Why do enterprises still use SAML—and where does it stop making sense?
* How do you **bridge SAML into JWT-based APIs and microservices**?
* Where should **application-specific entitlements** live?
* How do **token exchange / on-behalf-of flows** fit into a SAML-first world?
* What responsibilities belong to the **IdP**, and which belong to the **application**?

Rather than relying on vendor diagrams or abstract descriptions, the lab implements **real flows with real data**, exposing every step along the way.

---

## What this lab demonstrates

### 1. SP-initiated SAML SSO (browser-based)

* An unauthenticated user requests a protected resource
* The SP initiates a SAML AuthnRequest
* The browser is redirected to the IdP
* The IdP authenticates the user
* A signed SAMLResponse is POSTed back to the SP
* The SP validates the assertion and creates a local session

This mirrors **real enterprise SSO** behaviour.

---

### 2. Clear separation of responsibilities

The lab reinforces the core SAML principle:

> **SAML is an authentication federation protocol, not a credential-passing protocol.**

* The SP never sees user credentials
* The IdP controls authentication strength and UX
* The SP consumes **claims**, not passwords

---

### 3. Transforming SAML identity into application tokens

After successful SAML login:

* The SP holds a **session-backed identity**
* That identity is transformed into a **JWT access token**
* SAML attributes become token claims
* The token is suitable for API-style authorization

This mirrors how many real systems bridge SAML into REST APIs.

---

### 4. Token exchange / delegation patterns

The lab includes an **emulated token exchange flow**:

* A primary user token is issued
* A second, down-scoped token is minted for a downstream service
* The exchanged token:

  * has a different audience
  * has a shorter lifetime
  * references the parent token
  * represents “on-behalf-of” delegation

This models:

* OAuth 2.0 Token Exchange (RFC 8693)
* PingAM / PingFederate token exchange behaviour
* Secure microservice-to-microservice calls

---

### 5. Realistic enterprise architecture thinking

Although SimpleSAMLphp is used locally, the lab is explicitly designed to map onto:

* **PingAM 7.x**
* **PingFederate**
* **ForgeRock AM**
* **ADFS / Azure AD (conceptually)**

The Node.js SP behaves like a real application sitting behind:

* ingress controllers
* gateways
* service meshes

---

## What has been achieved

By the end of this lab, we have:

* A functioning **SAML Service Provider**
* A working **IdP-initiated and SP-initiated login flow**
* Fully validated SAML assertions
* A clean **post-SAML application session**
* A **JWT minting endpoint** derived from SAML identity
* A **token exchange endpoint** simulating on-behalf-of flows
* Clear documentation of:

  * endpoints
  * metadata
  * cookies vs tokens
  * browser-mediated transport
  * trust boundaries

Most importantly, we now have a **mental model that scales** from:

> “SAML login works”

to

> “This is how identity flows through a modern distributed system.”

---

## What this lab is *not*

This lab intentionally does **not**:

* implement a production-grade IdP
* recommend storing JWTs in localStorage for real systems
* replace OAuth/OIDC with SAML for APIs
* collapse IdP and application responsibilities

Instead, it makes those **trade-offs explicit and visible**.

---

## Who this lab is for

This repository is most useful for:

* engineers integrating enterprise SSO into modern apps
* architects bridging legacy IAM into microservices
* developers who have “used SAML” but never *understood* it
* teams evaluating PingAM / PingFederate / ForgeRock-style setups
* anyone designing **secure token exchange and delegation flows**

---

# SAML

## The core SAML rule (by design)

**SAML is an authentication *federation* protocol, not a credential-passing protocol.**

That means:

* The **SP never sees user credentials**
* The **IdP is the only party allowed to authenticate the user**
* The SP only receives a **signed assertion** saying *“this user is authenticated”*

This separation is the entire security value of SAML.

---

## What an SP is allowed to do

### ✅ What *is* allowed (standard SP-initiated login)

1. SP redirects the browser to the IdP SSO endpoint with an **AuthnRequest**
2. IdP decides *how* to authenticate the user
3. IdP returns a **SAMLResponse** to the SP

The IdP may authenticate the user via:

* Username/password UI
* MFA
* Smart card
* Kerberos / Windows Integrated Auth
* Existing IdP session (SSO)
* Any other IdP-controlled mechanism

But the **SP never supplies credentials**.

---

## What is *not* allowed in standard SAML

### ❌ SP posting credentials to IdP

There is **no supported way** for an SP to do:

```http
POST /idp/login
username=alice
password=secret
```

and get back a SAML assertion.

Why:

* SAML bindings (Redirect, POST, Artifact) **do not define credential parameters**
* IdPs intentionally reject this to prevent credential harvesting
* It would collapse the trust boundary SAML exists to enforce

If an IdP allowed this, it would be a serious security smell.

---

## “But surely there must be exceptions?”

There are — but they’re **specialised profiles**, not the normal web SSO flow.

### 1. **ECP (Enhanced Client or Proxy) – rare**

* Designed for **non-browser clients**
* Uses SOAP, not redirects
* SP ↔ client ↔ IdP exchange XML directly
* Credentials may be handled by the *client*, not the SP
* Almost never used in modern web apps

If you’re building a browser app: **ignore ECP**.

---

### 2. **IdP-initiated login**

* User starts at the IdP UI
* IdP redirects to SP with a SAMLResponse
* Still **no credential injection by the SP**

This is just a different starting point, not credential passing.

---

### 3. **Kerberos / IWA (Windows Integrated Authentication)**

* User has already authenticated to the IdP via domain login
* No login UI appears
* But the SP still **never passes credentials**

The IdP authenticates silently using environment trust, not SP input.

---

### 4. **Non-SAML APIs (important distinction)**

Some IdPs expose **non-SAML APIs** where credentials *can* be exchanged:

* OAuth2 Resource Owner Password Credentials (ROPC)
* LDAP bind
* Custom REST login endpoints

But these are **not SAML** and do **not produce SAML assertions** directly.

Many platforms support both:

* **SAML** for browser SSO
* **OAuth / LDAP** for API-style authentication

Different protocols, different trust models.

---

## Why your instinct matters (and is correct)

You’re thinking like an API designer:

> “In Node.js APIs we verify credentials and return the result to the frontend”

That model is **explicitly what SAML avoids**.

In SAML:

* Credential handling is **outsourced**
* Risk is **centralised in the IdP**
* The SP becomes a consumer of *claims*, not credentials

This is why enterprises like SAML.

---

## The only correct way for an SP to “trigger login”

The SP can only say:

> “I need the user authenticated”

and the IdP decides:

* whether to show UI
* which factors to require
* whether the user is already authenticated

The SP cannot say:

> “Authenticate *this* user with *these* credentials”

---

## Practical conclusion for your architecture

* ✅ **Frontend** redirects user to `/login` on your SP
* ✅ **SP** redirects browser to IdP SSO endpoint
* ✅ **IdP** authenticates user (UI or silent)
* ✅ **SP** receives assertion and creates session/JWT

If you ever find yourself wanting to pass credentials to the IdP:

* you either want **OAuth**, **OIDC**, or **LDAP**
* or you’re solving a different problem than SAML is meant for

---

## One-line rule to remember

> **If the SP knows the user’s password, you are no longer doing SAML.**

## SAML its not “magic redirects” its **formal contract** between two systems. I’ll do this in two parts:

1. **Walk through the metadata line-by-line** and explain *exactly* what the IdP learns from it
2. **Provide a compact glossary** of the SAML metadata elements and how SPs/IdPs use them

I’ll also correct or nuance a couple of assumptions along the way.

[Our reference SAML](#metadataSAML)


```xml
<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="http://localhost:3000/metadata" ID="_5889bfa5ce180985b47f0dbe6777bb93f9d6f234">
    <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true" WantAssertionsSigned="true">
        <KeyDescriptor use="signing">
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>MIIDtTCCAp2gAwIBAgIUfxO2zKI+znJ5ZOb0T9hzhlukfOkwDQYJKoZIhvcNAQEL
                    BQAwdTELMAkGA1UEBhMCR0IxGDAWBgNVBAgMD05vcnRoIFlvcmtzaGlyZTEUMBIG
                    A1UEBwwLU2NhcmJvcm91Z2gxFTATBgNVBAoMDERldiBTQU1MIExhYjELMAkGA1UE
                    ...
                    ad+/NIxJq7AwRxhpyM1t7MBbuuDlsVvGe6DIdgpK7d5x2Lbvaqn2Cmw=
                    </ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </KeyDescriptor>
        <KeyDescriptor use="encryption">
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>MIIDtTCCAp2gAwIBAgIUTh4xuG1g/ovgUSj69O+8g7rTreUwDQYJKoZIhvcNAQEL
                    BQAwdTELMAkGA1UEBhMCR0IxGDAWBgNVBAgMD05vcnRoIFlvcmtzaGlyZTEUMBIG
                    A1UEBwwLU2NhcmJvcm91Z2gxFTATBgNVBAoMDERldiBTQU1MIExhYjELMAkGA1UE
                    ...
                    +Zd/pbvfTRDO1+6BBj70iJXHjrpFEONZBwL2ZVmi2J8DrM0Z+hZmxsk=
                    </ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
            <EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
            <EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
            <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
            <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
        </KeyDescriptor>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
        <AssertionConsumerService index="1" isDefault="true" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:3000/login/callback"/>
    </SPSSODescriptor>
</EntityDescriptor>

```

---

# Part 1 — Explaining *your* SP metadata, element by element

Think of SP metadata as:

> **“This is who I am, how to talk to me, and which cryptographic keys you may trust from me.”**

Nothing here is secret.

---

## `<EntityDescriptor …>`

```xml
<EntityDescriptor
  xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
  entityID="http://localhost:3000/metadata"
  ID="_5889bfa5ce180985b47f0dbe6777bb93f9d6f234">
```

### Purpose

This is the **root identity of the SP**.

### Key attributes

* **`entityID`**

  * The **global identifier** of your SP
  * Must be **stable** and **unique**
  * Used by the IdP as:

    * Audience restriction
    * Trust anchor
    * Lookup key for configuration
  * Does *not* have to be a resolvable URL (but often is)

* **`ID`**

  * Internal XML identifier
  * Rarely used outside XML signature contexts

### What the IdP learns

> “This SP is called `http://localhost:3000/metadata`. Any assertions I issue to it must be scoped to that identifier.”

---

## `<SPSSODescriptor …>`

```xml
<SPSSODescriptor
  protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
  AuthnRequestsSigned="true"
  WantAssertionsSigned="true">
```

### Purpose

Declares that this entity acts as a **Service Provider for SAML SSO**.

### Attributes

* **`protocolSupportEnumeration`**

  * Says: “I speak SAML 2.0”
  * (Almost always this value)

* **`AuthnRequestsSigned="true"`**

  * You are telling the IdP:

    > “When I send AuthnRequests, I will sign them.”
  * If the IdP enforces this, it must have your **signing certificate**.

* **`WantAssertionsSigned="true"`**

  * You are telling the IdP:

    > “I require assertions to be signed.”
  * This is a **security requirement**, not a preference.

### What the IdP learns

> “I must verify SP-signed requests, and I must sign assertions I issue to this SP.”

---

## `<KeyDescriptor use="signing">`

```xml
<KeyDescriptor use="signing">
  <ds:KeyInfo>
    <ds:X509Data>
      <ds:X509Certificate>…</ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
</KeyDescriptor>
```

### Purpose

Publishes your **SP signing public key**.

### How it’s used

* IdP uses this key to:

  * Verify **signed AuthnRequests**
  * Verify **signed LogoutRequests** (if SLO used)

### Important clarifications

* This is **not** a TLS cert
* This is **not** a secret
* The IdP stores it and trusts signatures made by your private key

### What the IdP learns

> “If a SAML message claims to be from this SP and verifies with this cert, I trust it.”

---

## `<KeyDescriptor use="encryption">`

```xml
<KeyDescriptor use="encryption">
  …
  <ds:X509Certificate>…</ds:X509Certificate>
  …
  <EncryptionMethod Algorithm="…"/>
</KeyDescriptor>
```

### Purpose

Publishes your **SP encryption public key**.

### How it’s used

* IdP uses this key to:

  * Encrypt assertions
  * Encrypt NameIDs (optional)

### EncryptionMethod elements

These advertise **which symmetric algorithms** your SP can handle:

* `aes256-gcm`
* `aes128-gcm`
* `aes256-cbc`
* `aes128-cbc`

The IdP chooses one it supports.

### What the IdP learns

> “If I encrypt assertions for this SP, I must use this public key and one of these algorithms.”

---

## `<NameIDFormat>`

```xml
<NameIDFormat>
  urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
</NameIDFormat>
```

### Purpose

Declares **which subject identifier formats you support**.

### Important nuance

This is:

* A **capability advertisement**, not a guarantee
* The IdP may still choose a different format if configured so

Common values:

* `emailAddress`
* `persistent`
* `transient`
* `unspecified`

### What the IdP learns

> “This SP can accept an email-address NameID.”

---

## `<AssertionConsumerService …>`

```xml
<AssertionConsumerService
  index="1"
  isDefault="true"
  Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  Location="http://localhost:3000/login/callback"/>
```

### Purpose

Tells the IdP **where and how** to send the SAMLResponse.

### Attributes

* **`Binding`**

  * HTTP-POST (most common, safest)
* **`Location`**

  * Your ACS endpoint
  * Must match exactly what your SP accepts
* **`index` / `isDefault`**

  * Supports multiple ACS endpoints (rare today)

### What the IdP learns

> “After authenticating the user, POST the SAMLResponse to this URL.”

---

# Part 2 — SAML Metadata Glossary (SP-focused)

Below is a concise glossary of the major metadata concepts and how they’re used.

---

## Core identity concepts

| Field                 | Meaning                  | Used by                      |
| --------------------- | ------------------------ | ---------------------------- |
| `entityID`            | Global identifier of SP  | IdP (audience, trust lookup) |
| `Issuer` (runtime)    | Who issued a message     | SP & IdP                     |
| `AudienceRestriction` | Who the assertion is for | SP validation                |

---

## Cryptography

| Field                            | Purpose                       | Direction |
| -------------------------------- | ----------------------------- | --------- |
| `KeyDescriptor use="signing"`    | Verify SP-signed requests     | IdP ← SP  |
| `KeyDescriptor use="encryption"` | Encrypt assertions            | IdP → SP  |
| `AuthnRequestsSigned`            | SP promises to sign requests  | SP → IdP  |
| `WantAssertionsSigned`           | SP requires signed assertions | IdP → SP  |

---

## Endpoints

| Field                      | Purpose                             |
| -------------------------- | ----------------------------------- |
| `AssertionConsumerService` | Where IdP posts SAMLResponse        |
| `SingleLogoutService`      | Where logout messages go (optional) |
| `Binding`                  | How messages are transported        |

---

## Subject identifiers

| Field          | Meaning                         |
| -------------- | ------------------------------- |
| `NameIDFormat` | Type of subject identifier      |
| `persistent`   | Stable, SP-scoped ID            |
| `transient`    | One-time, privacy-preserving ID |
| `emailAddress` | Human-readable ID               |

---

## Runtime SAML fields (not in metadata)

| Field          | Purpose                                 |
| -------------- | --------------------------------------- |
| `SAMLRequest`  | AuthnRequest from SP                    |
| `SAMLResponse` | Assertion bundle from IdP               |
| `RelayState`   | Opaque state preserved across redirects |
| `InResponseTo` | Correlates response to request          |
| `SessionIndex` | Used for Single Logout                  |

---

# Final mental model (important)

Metadata is **not an API**.
It is a **trust contract**.

* It is exchanged **out-of-band**
* It enables **runtime messages to be trusted**
* It rarely changes
* It contains **no secrets**

Once exchanged, runtime SAML flows only reference:

* `entityID`
* endpoints
* keys

---

If you want, next we can:

* compare this SP metadata to **Ping / ForgeRock / ADFS UI fields**
* show how IdPs internally map this XML into config objects
* design **multi-tenant SP metadata** (per-customer entityIDs)
* or map SAML concepts to **OIDC equivalents** for intuition

Just say where you want to go next.


# Our SAML App setup


## Running our example in docker

Note: we're using 18080 and 19443 as on the test system ports 8080 and 8443 were already in use.  Our SP (nodejs application) is available on port 3000

```bash
docker run --platform linux/amd64 --rm --name saml-idp -p 18080:8080 -p 19443:8443 -e SIMPLESAMLPHP_SP_ENTITY_ID=http://localhost:3000/metadata -e SIMPLESAMLPHP_SP_ASSERTION_CONSUMER_SERVICE=http://localhost:3000/login/callback -e SIMPLESAMLPHP_SP_SINGLE_LOGOUT_SERVICE=http://localhost:3000/logout/callback kristophjunge/test-saml-idp
```
ref: https://github.com/kristophjunge/docker-test-saml-idp/tree/master

Running our Nodejs SP app
```bash
npx ts-node-dev src/saml/saml.ts
```

Terminal should respond with: 
```
[INFO] 16:19:11 ts-node-dev ver. 2.0.0 (using ts-node ver. 10.9.2, typescript ver. 5.9.3)
SP listening on http://localhost:3000
```

## How the keys were generated

For packages Passport.js will be using: `@node-saml/passport-saml@5.1.0` / `@node-saml/node-saml@5.1.0`

* **publish** both SP certs in metadata via `generateServiceProviderMetadata(decryptionCert, signingCert)`
* **actually use** them at runtime by adding:

  * `privateKey` (signing key)
  * `decryptionPvk` (decryption private key)
---

## 1) Generate cert/key files (signing + encryption)

From project root:

```bash
mkdir -p saml-certs
cd saml-certs
```

Create an OpenSSL config `openssl-localhost.cnf`:

```conf
[ req ]
default_bits       = 2048
default_md         = sha256
prompt             = no
distinguished_name = dn
req_extensions     = req_ext

[ dn ]
C  = GB
ST = North Yorkshire
L  = Scarborough
O  = Dev SAML Lab
OU = SP
CN = localhost

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1  = 127.0.0.1
```

### Signing keypair

```bash
openssl genrsa -out sp-signing.key 2048
openssl req -new -key sp-signing.key -out sp-signing.csr -config openssl-localhost.cnf
openssl x509 -req -in sp-signing.csr -signkey sp-signing.key \
  -out sp-signing.crt -days 825 -sha256 -extensions req_ext -extfile openssl-localhost.cnf
```

### Encryption keypair

```bash
openssl genrsa -out sp-encryption.key 2048
openssl req -new -key sp-encryption.key -out sp-encryption.csr -config openssl-localhost.cnf
openssl x509 -req -in sp-encryption.csr -signkey sp-encryption.key \
  -out sp-encryption.crt -days 825 -sha256 -extensions req_ext -extfile openssl-localhost.cnf
```

You now have:

* `saml-certs/sp-signing.key` + `saml-certs/sp-signing.crt`
* `saml-certs/sp-encryption.key` + `saml-certs/sp-encryption.crt`

---

## 2) Update your `PassportSamlConfig` (runtime signing + decryption)

```ts
const signingKey = fs.readFileSync(path.join(process.cwd(), "saml-certs/sp-signing.key"), "utf8");
const signingCert = fs.readFileSync(path.join(process.cwd(), "saml-certs/sp-signing.crt"), "utf8");

const decryptionKey = fs.readFileSync(path.join(process.cwd(), "saml-certs/sp-encryption.key"), "utf8");
const decryptionCert = fs.readFileSync(path.join(process.cwd(), "saml-certs/sp-encryption.crt"), "utf8");

export const passportSamlConfig: PassportSamlConfig = {
  ...
  // ✅ SP signing (used to sign AuthnRequests if you enable signing)
  privateKey: signingKey,
  signatureAlgorithm: "sha256",
  digestAlgorithm: "sha256",

  // ✅ SP decryption (used to decrypt encrypted assertions if IdP encrypts)
  decryptionPvk: decryptionKey,
  ...
};
```

## 3) Publish both certs in SP metadata

In your `/metadata` route, pass **public certs** (the `.crt` files):

```ts
app.get("/metadata", (_req, res) => {
  res.type("application/xml");
  res.send(samlStrategy.generateServiceProviderMetadata(decryptionCert, signingCert));
});
```

That produces metadata containing:

* `<KeyDescriptor use="encryption">…</KeyDescriptor>`
* `<KeyDescriptor use="signing">…</KeyDescriptor>`

---


## Calling the endpoints

routes are:

* `GET /` (home)
* `GET /login`
* `GET /metadata`
* `POST /login/callback` (ACS)
* `GET /me`
* `POST /logout` (app logout)
* `GET /login/fail`
* `GET/POST /debug/*`

---

## `/metadata` — Service Provider metadata (configuration contract)

Viewing metadata → `http://localhost:3000/metadata`

This endpoint publishes **public SP metadata** (XML) that an IdP admin imports to register your SP. It typically contains:

* `entityID` (your SP identifier)
* ACS endpoint (`/login/callback`)
* optional SLO endpoints
* your **public** signing/encryption certificates (`<KeyDescriptor …>`)
* flags like `AuthnRequestsSigned` / `WantAssertionsSigned`

It is **not part of the runtime login loop**. The IdP does **not** call `/metadata` during login; it’s used out-of-band for setup.

```ts
app.get("/metadata", (_req, res) => {
  res.type("application/xml");
  res.send(
    samlStrategy.generateServiceProviderMetadata(
      decryptionCert, // SP public encryption cert (crt)
      signingCert     // SP public signing cert (crt)
    )
  );
});
```

The IdP at http://localhost:18080/simplesaml/saml2/idp/metadata.php?output=xhtml

Example IdP metadata

```xml
<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="http://localhost:18080/simplesaml/saml2/idp/metadata.php">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIDXTCCAkWgAwIBAgIJALmVVuDWu4NYMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTYxMjMxMTQzNDQ3WhcNNDgwNjI1MTQzNDQ3WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzUCFozgNb1h1M0jzNRSCjhOBnR+uVbVpaWfXYIR+AhWDdEe5ryY+CgavOg8bfLybyzFdehlYdDRgkedEB/GjG8aJw06l0qF4jDOAw0kEygWCu2mcH7XOxRt+YAH3TVHa/Hu1W3WjzkobqqqLQ8gkKWWM27fOgAZ6GieaJBN6VBSMMcPey3HWLBmc+TYJmv1dbaO2jHhKh8pfKw0W12VM8P1PIO8gv4Phu/uuJYieBWKixBEyy0lHjyixYFCR12xdh4CA47q958ZRGnnDUGFVE1QhgRacJCOZ9bd5t9mr8KLaVBYTCJo5ERE8jymab5dPqe5qKfJsCZiqWglbjUo9twIDAQABo1AwTjAdBgNVHQ4EFgQUxpuwcs/CYQOyui+r1G+3KxBNhxkwHwYDVR0jBBgwFoAUxpuwcs/CYQOyui+r1G+3KxBNhxkwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAAiWUKs/2x/viNCKi3Y6blEuCtAGhzOOZ9EjrvJ8+COH3Rag3tVBWrcBZ3/uhhPq5gy9lqw4OkvEws99/5jFsX1FJ6MKBgqfuy7yh5s1YfM0ANHYczMmYpZeAcQf2CGAaVfwTTfSlzNLsF2lW/ly7yapFzlYSJLGoVE+OHEu8g5SlNACUEfkXw+5Eghh+KzlIN7R6Q7r2ixWNFBC/jWf7NKUfJyX8qIG5md1YUeT6GBW9Bm2/1/RiO24JTaYlfLdKK9TYb8sG5B+OLab2DImG99CJ25RkAcSobWNF5zD0O6lgOo3cEdB/ksCq3hmtlC/DlLZ/D8CJ+7VuZnS1rR2naQ==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIDXTCCAkWgAwIBAgIJALmVVuDWu4NYMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTYxMjMxMTQzNDQ3WhcNNDgwNjI1MTQzNDQ3WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzUCFozgNb1h1M0jzNRSCjhOBnR+uVbVpaWfXYIR+AhWDdEe5ryY+CgavOg8bfLybyzFdehlYdDRgkedEB/GjG8aJw06l0qF4jDOAw0kEygWCu2mcH7XOxRt+YAH3TVHa/Hu1W3WjzkobqqqLQ8gkKWWM27fOgAZ6GieaJBN6VBSMMcPey3HWLBmc+TYJmv1dbaO2jHhKh8pfKw0W12VM8P1PIO8gv4Phu/uuJYieBWKixBEyy0lHjyixYFCR12xdh4CA47q958ZRGnnDUGFVE1QhgRacJCOZ9bd5t9mr8KLaVBYTCJo5ERE8jymab5dPqe5qKfJsCZiqWglbjUo9twIDAQABo1AwTjAdBgNVHQ4EFgQUxpuwcs/CYQOyui+r1G+3KxBNhxkwHwYDVR0jBBgwFoAUxpuwcs/CYQOyui+r1G+3KxBNhxkwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAAiWUKs/2x/viNCKi3Y6blEuCtAGhzOOZ9EjrvJ8+COH3Rag3tVBWrcBZ3/uhhPq5gy9lqw4OkvEws99/5jFsX1FJ6MKBgqfuy7yh5s1YfM0ANHYczMmYpZeAcQf2CGAaVfwTTfSlzNLsF2lW/ly7yapFzlYSJLGoVE+OHEu8g5SlNACUEfkXw+5Eghh+KzlIN7R6Q7r2ixWNFBC/jWf7NKUfJyX8qIG5md1YUeT6GBW9Bm2/1/RiO24JTaYlfLdKK9TYb8sG5B+OLab2DImG99CJ25RkAcSobWNF5zD0O6lgOo3cEdB/ksCq3hmtlC/DlLZ/D8CJ+7VuZnS1rR2naQ==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://localhost:18080/simplesaml/saml2/idp/SingleLogoutService.php"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://localhost:18080/simplesaml/saml2/idp/SSOService.php"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
```

---

## `/` — Home / entry point (UI convenience)

Visiting home → `http://localhost:3000/`

This is just a convenience page with links to start login and view the authenticated profile.

```ts
app.get("/", (_req, res) => {
  res.send(`<a href="/login">Login with SAML</a> | <a href="/me">/me</a>`);
});
```

---

## `/login` — Start SP-initiated SSO

Start login → `http://localhost:3000/login`

This endpoint kicks off **SP-initiated SAML login**:

1. The SP constructs an **AuthnRequest** (XML)
2. The SP returns a **302 redirect** to the IdP’s SSO endpoint with a `SAMLRequest` query parameter (HTTP-Redirect binding)
3. The browser follows the redirect to the IdP login experience

Nothing is “posted” directly to the IdP from your server; the browser carries the request.

```ts
app.get(
  "/login",
  passport.authenticate("saml", { failureRedirect: "/login/fail" })
);
```

What gets generated under the hood (high-level):

* `SAMLRequest` = deflated + base64 encoded AuthnRequest
* `RelayState` = optional opaque state (used to return to a specific URL)
* Optional request signature if configured with `privateKey`

On the IdP server, there are two static users configured with the following data:

UID	Username	Password	Group	Email
1	user1	user1pass	group1	user1@example.com
2	user2	user2pass	group2	user2@example.com

---

## `/login/callback` — Assertion Consumer Service (ACS)

SAML callback (IdP POST target) → `http://localhost:3000/login/callback`

This is your **ACS endpoint**. After the user authenticates at the IdP, the IdP returns an HTML form that auto-submits a POST to this endpoint (HTTP-POST binding) containing:

* `SAMLResponse` = base64 encoded XML `<Response>` with `<Assertion>`
* `RelayState` = the same value from the original `/login` initiation (if present)

The SP then:

* parses the SAMLResponse
* verifies signatures using `idpCert` (IdP signing cert)
* validates conditions (time, audience, recipient)
* decrypts assertions if enabled (`decryptionPvk`)
* produces a normalized `profile`
* calls your verify callback (`done(null, profile)`)
* creates a local session (Passport) and redirects you onward

```ts
app.post(
  "/login/callback",
  passport.authenticate("saml", { failureRedirect: "/login/fail" }),
  (_req, res) => res.redirect("/me")
);
```

---

## `/me` — Protected resource (requires authenticated session)

View current user profile → `http://localhost:3000/me`

This endpoint demonstrates authorization gating using Passport’s session state:

* `req.isAuthenticated()` is true only after successful SAML login + session creation
* `req.user` contains the SAML profile (issuer, NameID, attributes, etc.)

```ts
function requireAuth(req: any, res: any, next: any) {
  if (req.isAuthenticated?.()) return next();
  return res.status(401).send("Not authenticated. Go to /login");
}

app.get("/me", requireAuth, (req: any, res) => {
  res.json({ user: req.user });
});
```

Sample response.
```json
{
  "user": {
    "issuer": "http://localhost:18080/simplesaml/saml2/idp/metadata.php",
    "inResponseTo": "_9f93a9fead7288e4257b47f2f1ed3b5b55069799",
    "sessionIndex": "_9a8d862c41a3dd6629698364916b78bed5a0cc3d1d",
    "nameID": "_7e5ddd916487bf629dd4bde55ce59f4198e1d3e8d3",
    "nameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    "spNameQualifier": "http://localhost:3000/metadata",
    "uid": "1",
    "eduPersonAffiliation": "group1",
    "email": "user1@example.com",
    "attributes": {
      "uid": "1",
      "eduPersonAffiliation": "group1",
      "email": "user1@example.com"
    }
  }
}
```

---

## `/logout` — Local app logout (clears SP session only)

Logout (local session) → `POST http://localhost:3000/logout`

This is **application logout**, not SAML Single Logout (SLO). It clears your Passport session, but the user may still have an active IdP session (meaning `/login` might SSO instantly next time).

```ts
app.post("/logout", (req: any, res) => {
  req.logout?.((err: any) => {
    if (err) return res.status(500).send(String(err));
    res.redirect("/");
  });
});
```

> If you want true “log out everywhere”, that’s SAML SLO (`SingleLogoutService`) and you’d add dedicated logout endpoints + IdP configuration.

---

## `/login/fail` — Authentication failure landing

Failure endpoint → `http://localhost:3000/login/fail`

Passport will send the user here if:

* the IdP response fails signature validation
* the response is malformed/expired
* the SP can’t correlate `InResponseTo` (depending on settings)
* any other SAML validation fails

```ts
app.get("/login/fail", (_req, res) => {
  res.status(401).send("SAML login failed");
});
```

---
Below is **copy-paste-ready Markdown** for each of the new debug routes, written in the same style as your existing `/metadata` section. I’ve kept it concise but precise, with enough context that a reader understands *why* the route exists and *what part of the SAML flow it helps explain*.

You can drop these directly into your README or internal docs.

---

## `/debug/whoami` — Authentication & session snapshot

Viewing auth/session state →

```http
GET http://localhost:3000/debug/whoami
```

This endpoint returns a **sanitised snapshot of the current authentication state** for the request.

It is useful for confirming:

* whether the request is authenticated (`req.isAuthenticated()`)
* whether a session exists
* whether `req.user` has been populated from a SAML assertion
* which high-level SAML fields are present (issuer, NameID, attributes)

It does **not** perform authentication and does **not** return sensitive assertion contents.

```ts
app.get("/debug/whoami", (req: any, res) => {
  const user = req.user ?? null;

  res.json({
    isAuthenticated: Boolean(req.isAuthenticated?.()),
    sessionID: req.sessionID ?? null,
    hasSession: Boolean(req.session),
    sessionKeys: req.session ? Object.keys(req.session) : [],
    userKeys: user ? Object.keys(user) : [],
    userSummary: user
      ? {
          issuer: user.issuer,
          nameID: user.nameID,
          nameIDFormat: user.nameIDFormat,
          sessionIndex: user.sessionIndex,
          attributesKeys: user.attributes ? Object.keys(user.attributes) : [],
        }
      : null,
  });
});
```

e.g.
```json
{
  "isAuthenticated": true,
  "sessionID": "9IuL9fzBKCSNlgse8YM1WaleozikkoNL",
  "hasSession": true,
  "sessionKeys": [
    "cookie",
    "passport"
  ],
  "userKeys": [
    "issuer",
    "inResponseTo",
    "sessionIndex",
    "nameID",
    "nameIDFormat",
    "spNameQualifier",
    "uid",
    "eduPersonAffiliation",
    "email",
    "attributes"
  ],
  "userSummary": {
    "issuer": "http://localhost:18080/simplesaml/saml2/idp/metadata.php",
    "nameID": "_7e5ddd916487bf629dd4bde55ce59f4198e1d3e8d3",
    "nameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    "sessionIndex": "_9a8d862c41a3dd6629698364916b78bed5a0cc3d1d",
    "attributesKeys": [
      "uid",
      "eduPersonAffiliation",
      "email"
    ]
  }
}
```

---

## `/debug/headers` — Request header inspection (sanitised)

Inspect request headers →

```http
GET http://localhost:3000/debug/headers
```

This endpoint returns a **sanitised view of the incoming HTTP request**, including:

* protocol and hostname
* client IP / forwarded IPs
* forwarded headers (`x-forwarded-*`)
* user agent

Sensitive headers (cookies, authorization headers) are redacted.

This is especially useful when debugging:

* reverse proxies / ingress controllers
* HTTPS termination
* host / proto mismatches that can break SAML destination validation

```ts
app.get("/debug/headers", (req, res) => {
  res.json({
    method: req.method,
    originalUrl: req.originalUrl,
    hostname: req.hostname,
    protocol: req.protocol,
    secure: req.secure,
    ip: req.ip,
    ips: (req as any).ips,
    headers: sanitizeHeaders(req.headers as any),
  });
});
```

e.g.
```json
{
  "method": "GET",
  "originalUrl": "/debug/headers",
  "hostname": "localhost",
  "protocol": "http",
  "secure": false,
  "ip": "::1",
  "ips": [],
  "headers": {
    "host": "localhost:3000",
    "sec-fetch-dest": "document",
    "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Safari/605.1.15",
    "upgrade-insecure-requests": "1",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "sec-fetch-site": "none",
    "sec-fetch-mode": "navigate",
    "accept-language": "en-GB,en;q=0.9",
    "priority": "u=0, i",
    "accept-encoding": "gzip, deflate",
    "cookie": "[REDACTED]",
    "connection": "keep-alive"
  }
}
```
---

## `/debug/login-init` — Preview IdP redirect (no redirect)

Preview SP-initiated SAML login →

```http
GET http://localhost:3000/debug/login-init
```

This endpoint shows **where the SP would redirect the browser** to initiate SAML login, **without actually performing the redirect**.

It allows you to inspect:

* the IdP SSO endpoint
* the presence of a generated `SAMLRequest`
* optional request signature parameters

This is useful for validating SP configuration without leaving the application or triggering an IdP login.

```ts
app.get("/debug/login-init", (req, res, next) => {
  const middleware = passport.authenticate("saml", {
    failureRedirect: "/login/fail",
  });

  const originalRedirect = res.redirect.bind(res);
  (res as any).redirect = (location: string) => {
    (res as any).redirect = originalRedirect;

    res.json({
      wouldRedirectTo: location,
      note:
        "This is the IdP SSO URL with SAMLRequest generated by the SP. No redirect was executed.",
    });
    return res;
  };

  middleware(req as any, res as any, next);
});
```

e.g.
```json
{
  "user": {
    "issuer": "http://localhost:18080/simplesaml/saml2/idp/metadata.php",
    "inResponseTo": "_0af5a19abe9408c88411efa8a6cda90d82c08866",
    "sessionIndex": "_4b84bc55503e507931964221061302cd2bb276f263",
    "nameID": "_81ee3fe343628b22ac7cdd3a05437a566fd7ed1e0f",
    "nameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    "spNameQualifier": "http://localhost:3000/metadata",
    "uid": "1",
    "eduPersonAffiliation": "group1",
    "email": "user1@example.com",
    "attributes": {
      "uid": "1",
      "eduPersonAffiliation": "group1",
      "email": "user1@example.com"
    }
  }
}
```
---

## `/debug/acs` — Safe SAMLResponse inspection (no validation)

Inspect incoming SAMLResponse →

```http
POST http://localhost:3000/debug/acs
```

This endpoint accepts a POSTed `SAMLResponse` and **inspects it safely** without:

* validating signatures
* decrypting assertions
* creating a session

It extracts only **high-level, non-sensitive fields**, such as:

* Issuer
* Destination
* InResponseTo
* whether an assertion or encrypted assertion is present

This is useful for:

* confirming what the IdP is posting
* validating ACS URL configuration
* debugging failed authentications without logging full assertions

> ⚠️ Dev-only. Do not enable in production.

```ts
app.post(
  "/debug/acs",
  bodyParser.urlencoded({ extended: false }),
  (req, res) => {
    const samlResponseB64 = req.body?.SAMLResponse;
    const relayState = req.body?.RelayState ?? null;

    if (!samlResponseB64) {
      return res.status(400).json({ error: "Missing SAMLResponse" });
    }

    const xml = Buffer.from(samlResponseB64, "base64").toString("utf8");
    const parsed = xmlParser.parse(xml);
    const extracted = safeExtract(parsed);

    res.json({
      receivedAt: new Date().toISOString(),
      relayState,
      samlResponse: {
        base64Length: samlResponseB64.length,
        xmlLength: xml.length,
        extracted,
      },
      note:
        "This endpoint inspects structure only. It does not authenticate or validate signatures.",
    });
  }
);
```

---

## `/debug/routes` — List registered Express routes

List all routes →

```http
GET http://localhost:3000/debug/routes
```

This endpoint enumerates all registered Express routes and HTTP methods.

It is useful for:

* confirming which routes are active
* validating that ACS, metadata, and debug routes are registered
* sanity-checking refactors or middleware ordering

```ts
app.get("/debug/routes", (_req, res) => {
  const routes: Array<{ method: string; path: string }> = [];

  (app as any)._router?.stack?.forEach((layer: any) => {
    if (layer?.route?.path && layer?.route?.methods) {
      const methods = Object.keys(layer.route.methods)
        .filter((m) => layer.route.methods[m])
        .map((m) => m.toUpperCase());

      for (const method of methods) {
        routes.push({ method, path: layer.route.path });
      }
    }
  });

  routes.sort((a, b) => (a.path + a.method).localeCompare(b.path + b.method));
  res.json({ routes });
});
```
e.g.

```json
{
  "routes": [
    { "method": "GET", "path": "/api/service-b/resource" },
    { "method": "POST", "path": "/api/token/exchange" },
    { "method": "GET", "path": "/" },
    { "method": "POST", "path": "/login/callback" },
  ]
}
```
---

Below is **copy-paste-ready Markdown** for the **two new JWT endpoints** (plus the optional protected resource), written in **exactly the same style** as your earlier route documentation.

You can drop these straight into your README or internal design docs.

---

## `/api/token/from-session` — Mint a JWT from the SAML-backed Express session

Mint an application access token →

```http
POST http://localhost:3000/api/token/from-session
```

This endpoint **transforms the authenticated Express session into a JWT**.

### Purpose

* Bridge **SAML authentication** (session-based) into **token-based API access**
* Capture the SAML-derived user profile and emit it as application-friendly claims
* Simulate the “IdP authenticated user → app access token” step

### Preconditions

* The user **must already be authenticated via SAML**
* A valid Express session must exist (`req.isAuthenticated() === true`)

### What it does

1. Reads the SAML profile from `req.user`
2. Selects a stable subject identifier (email / uid / fallback)
3. Copies relevant SAML fields into JWT claims:

   * issuer
   * NameID
   * attributes (email, uid, groups)
4. Signs a JWT (HS256, dev-only)
5. Returns the token as JSON

### Example response

```json
{
    "tokenType": "Bearer",
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzYW1sLXNwLWRldiIsImF1ZCI6ImZyb250ZW5kIiwic3ViIjoidXNlcjFAZXhhbXBsZS5jb20iLCJpYXQiOjE3NzA3MzE1MTYsImV4cCI6MTc3MDczMjQxNiwianRpIjoidG9rXzk3ZGJhMzI0LTA0MWUtNGNiZi1iMTRhLWU3NjU5MDM3Yzg0YSIsImlkcF9pc3MiOiJodHRwOi8vbG9jYWxob3N0OjE4MDgwL3NpbXBsZXNhbWwvc2FtbDIvaWRwL21ldGFkYXRhLnBocCIsInNhbWxfaW5fcmVzcG9uc2VfdG8iOiJfMGFmNWExOWFiZTk0MDhjODg0MTFlZmE4YTZjZGE5MGQ4MmMwODg2NiIsInNhbWxfc2Vzc2lvbl9pbmRleCI6Il80Yjg0YmM1NTUwM2U1MDc5MzE5NjQyMjEwNjEzMDJjZDJiYjI3NmYyNjMiLCJzYW1sX25hbWVpZCI6Il84MWVlM2ZlMzQzNjI4YjIyYWM3Y2RkM2EwNTQzN2E1NjZmZDdlZDFlMGYiLCJzYW1sX25hbWVpZF9mb3JtYXQiOiJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDp0cmFuc2llbnQiLCJzYW1sX3NwX25hbWVfcXVhbGlmaWVyIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwL21ldGFkYXRhIiwiZW1haWwiOiJ1c2VyMUBleGFtcGxlLmNvbSIsInVpZCI6IjEiLCJncm91cHMiOlsiZ3JvdXAxIl0sImF0dHJpYnV0ZXMiOnsidWlkIjoiMSIsImVkdVBlcnNvbkFmZmlsaWF0aW9uIjoiZ3JvdXAxIiwiZW1haWwiOiJ1c2VyMUBleGFtcGxlLmNvbSJ9fQ.aIAqZsHwZ0r4UsZdrOREsS_awviFOsMtFD-Kv2UO67g",
    "expiresIn": 900,
    "storageKeySuggested": "access_token_primary",
    "note": "Dev endpoint. Client stores in localStorage."
}
```

### Typical client usage

```js
await fetch("/api/token/from-session", { method: "POST" })
  .then(r => r.json())
  .then(d => localStorage.setItem("access_token_primary", d.accessToken));
```

### Notes

* This token represents **application identity**, not SAML
* In production, this would usually be:

  * short-lived
  * signed with an asymmetric key
  * stored in an httpOnly cookie or BFF

---

## `/api/token/exchange` — Emulate token exchange / on-behalf-of flow

Exchange one token for another →

```http
POST http://localhost:3000/api/token/exchange
Authorization: Bearer <primary-token>
```

This endpoint **emulates OAuth 2.0 Token Exchange** (RFC 8693–style) without calling PingAM.

### Purpose

* Demonstrate **token exchange / delegation**
* Produce a **down-scoped token** for a downstream service
* Simulate “Service A calls Service B on behalf of the user”

### Preconditions

* A valid bearer token issued by `/api/token/from-session`
* Token must pass signature + issuer validation

### What it does

1. Validates the incoming bearer token
2. Extracts identity claims (`sub`, email, groups)
3. Mints a **new token** with:

   * different `aud` (target service)
   * new `jti`
   * shorter expiry
   * link to the parent token
4. Adds a toy `act` (actor) claim to represent delegation
5. Returns the exchanged token as JSON

### Example response

```json
{
    "tokenType": "Bearer",
    "exchangedToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzYW1sLXNwLWRldiIsImF1ZCI6InNlcnZpY2UtYiIsInN1YiI6InVzZXIxQGV4YW1wbGUuY29tIiwiaWF0IjoxNzcwNzMxOTEzLCJleHAiOjE3NzA3MzIyMTMsImp0aSI6InhjaGdfZTMxYTI5MjUtN2VjOC00MGUzLTliODQtMmQ1MTJiZjMzNGRlIiwicGFyZW50X2p0aSI6InRva185N2RiYTMyNC0wNDFlLTRjYmYtYjE0YS1lNzY1OTAzN2M4NGEiLCJhY3QiOnsic3ViIjoic2VydmljZS1hIn0sImVtYWlsIjoidXNlcjFAZXhhbXBsZS5jb20iLCJ1aWQiOiIxIiwiZ3JvdXBzIjpbImdyb3VwMSJdLCJzdmNfcGVybWlzc2lvbnMiOlsicmVhZDpwYXRpZW50cyIsInJlYWQ6c2l0ZXMiXSwiaWRwX2lzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6MTgwODAvc2ltcGxlc2FtbC9zYW1sMi9pZHAvbWV0YWRhdGEucGhwIn0.0dhlZmRZRUUotXVfpMS6l6VGvq5ueWGQhuoKAGk2a_g",
    "expiresIn": 300,
    "storageKeySuggested": "access_token_exchanged",
    "note": "Dev-only token exchange emulation (not calling PingAM)."
}
```

### Typical client usage

```js
await fetch("/api/token/exchange", {
  method: "POST",
  headers: {
    Authorization: `Bearer ${localStorage.getItem("access_token_primary")}`
  }
})
  .then(r => r.json())
  .then(d => localStorage.setItem("access_token_exchanged", d.exchangedToken));
```

### Notes

* This endpoint **does not** call PingAM
* In a real deployment:

  * PingAM’s token endpoint would perform the exchange
  * Policy (`may_act`, audience, scope) would be enforced centrally

---

## `/api/service-b/resource` — Protected downstream API (optional demo)

Access a service protected by an exchanged token →

```http
GET http://localhost:3000/api/service-b/resource
Authorization: Bearer <exchanged-token>
```

This endpoint simulates a **downstream microservice** that:

* Requires a token with a specific audience
* Does **not** accept the original user-facing token

### What it checks

* Token signature and issuer
* Token audience matches the service (`aud === "service-b"`)

### Example response

```json
{
    "ok": true,
    "claims": {
        "iss": "saml-sp-dev",
        "aud": "service-b",
        "sub": "user1@example.com",
        "iat": 1770731913,
        "exp": 1770732213,
        "jti": "xchg_e31a2925-7ec8-40e3-9b84-2d512bf334de",
        "parent_jti": "tok_97dba324-041e-4cbf-b14a-e7659037c84a",
        "act": {
            "sub": "service-a"
        },
        "email": "user1@example.com",
        "uid": "1",
        "groups": [
            "group1"
        ],
        "svc_permissions": [
            "read:patients",
            "read:sites"
        ],
        "idp_iss": "http://localhost:18080/simplesaml/saml2/idp/metadata.php"
    }
}
```

# SAML SP → IdP → SP: Complete Flow Walkthrough

This document explains how the Service Provider (SP) and Identity Provider (IdP) interact during a **browser-based, SP-initiated SAML login**, using the endpoints implemented in this application.

---

## 1️⃣ End-to-end flow walkthrough (what happens, in order)

### Actors

* **Browser** – user agent (Chrome, Safari, etc.)
* **SP** – Node.js / Express app (this repo)
* **IdP** – SimpleSAMLphp (or any enterprise IdP)

---

### Step 0 — User requests a protected resource

```http
GET http://localhost:3000/me
```

* Express middleware checks `req.isAuthenticated()`
* User is **not authenticated**
* Application redirects to `/login`

No SAML involved yet.

---

### Step 1 — SP initiates SAML login

```http
GET http://localhost:3000/login
```

Code path:

```ts
passport.authenticate("saml")
```

What happens internally:

* SP generates a **SAML AuthnRequest (XML)**
* Request may be **signed** using SP private key
* SP responds with **HTTP 302 redirect** to IdP

Browser receives:

```http
302 Location: http://localhost:18080/simplesaml/saml2/idp/SSOService.php?SAMLRequest=...
```

At this point:

* The SP is done
* The browser carries the request to the IdP

---

### Step 2 — IdP authenticates the user

```http
GET http://localhost:18080/simplesaml/saml2/idp/SSOService.php?SAMLRequest=...
```

* IdP validates AuthnRequest (issuer, signature, ACS)
* IdP shows **login UI** (unless user already has IdP session)
* User authenticates (e.g. `user1/password`)

---

### Step 3 — IdP returns a SAMLResponse to the SP

After successful login, the IdP returns HTML that auto-submits a form:

```http
POST http://localhost:3000/login/callback
Content-Type: application/x-www-form-urlencoded

SAMLResponse=BASE64_XML
RelayState=...
```

Important:

* This POST is sent by the **browser**
* The IdP never calls the SP directly

---

### Step 4 — SP validates assertion and creates a session

```ts
passport.authenticate("saml")
```

SP performs:

* Base64 decode → XML parse
* XML signature verification using **IdP signing cert**
* Optional assertion decryption using SP private key
* Validation of:

  * `InResponseTo`
  * `Audience`
  * `Destination`
  * time conditions
* Calls verify callback → `done(null, profile)`

Passport then:

* Sets `req.user`
* Creates Express session
* Sets session cookie

SP redirects user:

```http
302 Location: /me
```

---

### Step 5 — Authenticated access

```http
GET http://localhost:3000/me
```

* Session cookie present
* `req.isAuthenticated()` → `true`
* `req.user` contains SAML profile
* Protected resource is returned

---

## 2️⃣ Sequence diagram (browser-centric SAML flow)

```
Browser                    SP (Node.js)                    IdP
   |                            |                           |
   | GET /me                    |                           |
   |--------------------------->|                           |
   |   401 / redirect           |                           |
   |<---------------------------|                           |
   | GET /login                 |                           |
   |--------------------------->|                           |
   | 302 to IdP w/              |                           |
   | SAMLRequest                |                           |
   |<---------------------------|                           |
   | GET /SSOService            |                           |
   |------------------------------------------------------->|
   |                Login UI    |                           |
   |<-------------------------------------------------------|
   | POST credentials (browser) |                           |
   |------------------------------------------------------->|
   | HTML response w/ auto-POST |                           |
   |<-------------------------------------------------------|
   | POST /login/callback (ACS) |                           |
   |--------------------------->|                           |
   |   Validate Response        |                           |
   |   Create session           |                           |
   | 302 /me                    |                           |
   |<---------------------------|                           |
   | GET /me                    |                           |
   |--------------------------->|                           |
   |   Protected data           |                           |
   |<---------------------------|                           |

```

Key insight:

> **The browser is the transport.**
> SP and IdP never make direct backend-to-backend calls during login.

---

## 3️⃣ Annotated SAML messages (what actually matters)

### A) AuthnRequest (SP → IdP)

Decoded from `SAMLRequest`:

```xml
<samlp:AuthnRequest
  ID="_632446bcc3f0073b6420bb80172e842d4b775152"
  IssueInstant="2026-02-10T10:12:03Z"
  Destination="http://localhost:18080/simplesaml/saml2/idp/SSOService.php"
  AssertionConsumerServiceURL="http://localhost:3000/login/callback"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">

  <saml:Issuer>
    http://localhost:3000/metadata
  </saml:Issuer>

  <samlp:NameIDPolicy
    Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    AllowCreate="true" />
</samlp:AuthnRequest>
```

#### What the IdP cares about

| Field         | Meaning                       |
| ------------- | ----------------------------- |
| `Issuer`      | Identifies the SP             |
| `Destination` | IdP SSO endpoint              |
| `ACS URL`     | Where to POST response        |
| `ID`          | Used for replay protection    |
| Signature     | If `AuthnRequestsSigned=true` |

---

### B) SAMLResponse (IdP → SP)

Decoded from `SAMLResponse`:

```xml
<samlp:Response
  InResponseTo="_632446bcc3f0073b6420bb80172e842d4b775152"
  Destination="http://localhost:3000/login/callback">

  <saml:Issuer>
    http://localhost:18080/simplesaml/saml2/idp/metadata.php
  </saml:Issuer>

  <saml:Assertion>
    <saml:Subject>
      <saml:NameID
        Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">
        _553a22946fb54da530fbc2cf1ebbcd304e0d4b888b
      </saml:NameID>
    </saml:Subject>

    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>user1@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="uid">
        <saml:AttributeValue>1</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

#### What the SP validates

| Field           | Why it matters           |
| --------------- | ------------------------ |
| `Issuer`        | Must match trusted IdP   |
| Signature       | Verified using IdP cert  |
| `InResponseTo`  | Must match request       |
| `Audience`      | Must include SP entityID |
| Time conditions | Prevent replay           |
| Attributes      | Mapped to `req.user`     |

---

## 4️⃣ Where metadata fits (important clarification)

* `/metadata` is **not called during login**
* It is used **out-of-band** by IdP admins to register the SP
* It defines:

  * SP identity (`entityID`)
  * ACS URL
  * Signing/encryption keys
  * Security requirements

Runtime login works **only because metadata was exchanged earlier** (manually, via URL, or via env-based test config).

---

## 5️⃣ What the frontend actually does (in practice)

The frontend:

* Never sees SAML
* Never sees assertions
* Never handles certificates

Typical behaviour:

1. Call `/api/me`
2. If 401 → `window.location.href = "/login"`
3. After redirect, retry `/api/me`

SAML ends at the backend boundary.

---

## Final mental model (worth remembering)

> **SAML is a browser-carried, XML-signed trust exchange.**
> **Your app session is created *after* SAML succeeds.**

# Appendicies

## passport.autenticate

At `/login/callback`, It authenticates using the **POSTed form body**, specifically the `SAMLResponse` field.

IdP added the `SimpleSAMLAuthTokenIdp` cookie, it's IdP’s own session cookie (scoped to the IdP domain). Your SP doesn’t need it and can’t reliably use it (and typically won’t even receive it).

### Why you see `SimpleSAMLAuthTokenIdp`

* When you’re on the IdP domain (`localhost:18080`), the IdP sets its own cookie to remember “user is logged into the IdP”.
* That cookie is sent by the browser **only to the IdP domain**.
* Your SP is on a different origin (`localhost:3000`), so that cookie is not part of your SP authentication.

If you *did* see it being sent to `localhost:3000`, that would be unusual and would imply the cookie domain/path were set very broadly (not the normal/secure configuration).

---

## What `passport.authenticate("saml")` actually does at `/login/callback`

When the browser auto-posts to your ACS endpoint, it posts:

```http
POST /login/callback
Content-Type: application/x-www-form-urlencoded

SAMLResponse=BASE64_XML
RelayState=...
```

At that point, `passport.authenticate("saml")` (via `@node-saml/passport-saml` / `@node-saml/node-saml`) does roughly this:

1. **Read the form**

* Looks at `req.body.SAMLResponse` (and sometimes `req.body.RelayState`)
* This requires `express.urlencoded()` middleware to have parsed the form body

2. **Decode and parse**

* Base64-decodes the SAMLResponse into XML
* Parses XML into objects

3. **Verify**

* Validates the XML signature using **`idpCert`**
* Validates conditions:

  * `Destination` matches your ACS URL (depending on options)
  * `InResponseTo` matches the request (if tracked)
  * assertion time window (NotBefore / NotOnOrAfter)
  * audience restriction includes your SP entityID

4. **(Optional) decrypt**

* If assertions are encrypted, uses `decryptionPvk` to decrypt

5. **Build a profile**

* Extracts NameID, issuer, attributes, sessionIndex, etc.
* Calls your verify callback: `done(null, profile)`

6. **Create your SP session**

* Passport calls `serializeUser(profile)` and stores a reference in your Express session
* Express sends back **your app’s session cookie** `connect.sid` e.g. `s%3Ar-n4mpPkIgAGiCV6IB3gskH9psshb2NZ.NwhvE2A%2BIN3WaMpLhKoEFEXoEPsX5TcdMeqoJrP5ivU`, not the IdP cookie

7. Your handler runs:

```ts
(_req, res) => res.redirect("/me")
```

---

## So what cookie does your SP use?

Your SP uses **its own session cookie**, typically something like:

* `connect.sid` (default express-session)

That cookie is set on the response from `/login/callback` and then included on subsequent requests (`/me`, etc.).

---

## Where the IdP cookie matters

The IdP cookie matters only for **IdP-side SSO**:

* If you hit `/login` again later, the SP redirects you to the IdP.
* If the IdP still has an active session cookie, it may skip the login screen and immediately issue a new SAMLResponse.

So the IdP cookie improves UX, but it’s not part of SP validation.

---

## After SAML assertion - IdP Token exchange

You’re describing two closely related patterns that modern IAM stacks (including PingAM / PingFederate) support:

1. **IdP/Authorization Server mints an access token with entitlements** (normal OAuth/OIDC token issuance), and
2. **Token Exchange / On-Behalf-Of** for “service A calls service B” and needs a *different* token (audience/scopes/subject changes), typically per **RFC 8693**. ([IETF Datatracker][1])

Below is a clear mental model and a concrete “who validates what” answer.

---

## 1) “IdP mints bearer token with entitlements” vs “application-specific claims”

### What the IdP *can* do well

If PingAM is acting as your OAuth/OIDC Authorization Server, it can mint tokens that include:

* standard identity claims (sub, email)
* groups/roles that exist in the directory
* coarse entitlements based on policy/rules configured centrally

That’s common.

### Why you still often need a token exchange / enrichment step

Your application-specific claims usually depend on *application data*:

* tenant/study/site boundaries
* per-study roles (sponsor vs CRO vs investigator)
* feature flags, consent state, trial enrolment status
* “call centre can access only these endpoints for these tenants”

Those tend to live in your app DB, not the IdP directory.

So a common architecture is:

**IdP token (identity + coarse claims) → App entitlement service → App token (fine-grained claims)**

This keeps the IdP from becoming the dumping ground for all business authorization data.

---

## 2) Microservice-to-microservice: “token exchange” is the right primitive

When Service A calls Service B “on behalf of user”, you generally don’t want A to forward the user’s original token unchanged because:

* **Audience mismatch**: token audience might be “gateway” or “frontend”, not “service-b”
* **Over-privilege**: token might have scopes/claims too broad for B
* **Propagation risk**: leaking a user token deeper into the mesh increases blast radius

Instead, you do an exchange to mint a **down-scoped**, **audience-bound** token for Service B.

This is precisely what **OAuth 2.0 Token Exchange (RFC 8693)** is for. ([IETF Datatracker][1])

---

## 3) Does the token exchanger validate the entry token “against the IdP”?

**It depends on what “token exchanger” is in your architecture.** There are two clean options:

### Option A (most standard): The IdP/AS *is* the token exchanger

You send the token to the **authorization server’s token endpoint** with:

* `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
* `subject_token=<incoming access token>`
* `subject_token_type=urn:ietf:params:oauth:token-type:access_token`
* plus `audience` / `scope` to shape the output token

RFC 8693 defines this pattern. ([IETF Datatracker][1])

Ping products explicitly support this:

* PingAM token exchange docs (mentions RFC 8693 and constraints like “exchange only at the provider that issued them”). ([Ping Identity Documentation][2])
* PingFederate supports “token exchange grant” and multiple token types. ([Ping Identity Documentation][3])

In this setup, the “token exchanger” *does not call out to the IdP*—it **is** the IdP/AS, so it validates locally (signature/claims/state/introspection as needed).

### Option B: You build a token exchange service (“STS”) in your platform

Then you must validate the incoming token before minting a new one. Common approaches:

* **JWT validation locally**: verify signature using IdP JWKS, validate `iss`, `aud`, `exp`, etc.
* **Introspection** (if tokens are opaque, or you need real-time revocation): call the IdP introspection endpoint

But note: RFC 8693 assumes token exchange happens at an authorization server/STS. Building your own STS is doable, but you’re now re-implementing a chunk of IAM.

---

## 4) The “on-behalf-of” controls: impersonation vs delegation

RFC 8693 distinguishes:

* **delegation** (“service acts for user, user remains subject”)
* **impersonation** (“service becomes the subject”)

Implementations use constraints so not every client can exchange any token. PingAM highlights the `may_act` claim as a cornerstone for controlling who can exchange/act. ([Ping Identity Documentation][4])

This is the policy lever that stops “any microservice can mint any token”.

---

## 5) Practical target architecture for your case

Given your multi-service platform and desire for service-to-service calls:

### Recommended baseline

* Frontend gets **user access token** (audience = gateway/BFF)
* Gateway/BFF validates it and issues a **session** or forwards it
* When Service A needs Service B:

  * Service A requests **token exchange** at PingAM/PingFederate token endpoint for `audience=service-b` and minimal `scope`
  * Service A calls Service B with exchanged token

This keeps:

* the IdP as the trust anchor (single place to mint/shape tokens)
* microservices receiving tokens tailored to them

---

## 6) One concrete rule of thumb

> **Validate locally where possible; exchange centrally.**
> Resource servers validate JWTs locally; token *exchange* happens at the AS/STS (PingAM/PF) so policy is centralized and aud/scope are correct.

---

[1]: https://datatracker.ietf.org/doc/html/rfc8693?utm_source=chatgpt.com "RFC 8693 - OAuth 2.0 Token Exchange"
[2]: https://docs.pingidentity.com/pingam/8/am-oauth2/token-exchange.html?utm_source=chatgpt.com "Token exchange | PingAM"
[3]: https://docs.pingidentity.com/pingfederate/13.0/introduction_to_pingfederate/pf_token_exchange_grant.html?utm_source=chatgpt.com "Token exchange grant | PingFederate Server"
[4]: https://docs.pingidentity.com/pingam//7.2/oauth2-guide/oauth2-token-exchange.html?utm_source=chatgpt.com "OAuth 2.0 token exchange | PingAM"
