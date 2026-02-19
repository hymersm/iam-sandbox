import express from "express";
import session from "express-session";
import bodyParser from "body-parser";
import passport from "passport";
import fs from "fs";
import path from "path";
import { Strategy as SamlStrategy, Profile, PassportSamlConfig, VerifiedCallback, VerifyWithRequest } from "@node-saml/passport-saml";

import jwt, { JwtPayload } from "jsonwebtoken";
import type { Request, Response, NextFunction } from "express";

const JWT_ISSUER = "saml-sp-dev";
const JWT_AUDIENCE_PRIMARY = "frontend";
const JWT_AUDIENCE_EXCHANGED = "service-b"; // example downstream service
const JWT_SECRET = process.env.JWT_SECRET || "dev-only-secret-change-me";

function nowEpoch() {
  return Math.floor(Date.now() / 1000);
}

function safeArray(v: any): string[] {
  if (v == null) return [];
  if (Array.isArray(v)) return v.map(String);
  return [String(v)];
}

const signingKey = fs.readFileSync(path.join(process.cwd(), "saml-certs/sp-signing.key"), "utf8");
const signingCert = fs.readFileSync(path.join(process.cwd(), "saml-certs/sp-signing.crt"), "utf8");

const decryptionKey = fs.readFileSync(path.join(process.cwd(), "saml-certs/sp-encryption.key"), "utf8");
const decryptionCert = fs.readFileSync(path.join(process.cwd(), "saml-certs/sp-encryption.crt"), "utf8");

const idpCert = fs.readFileSync(path.join(process.cwd(), "saml-certs/idp.crt"), "utf8");

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));

app.use(
  session({
    secret: "dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: false },
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user: any, done) => done(null, user));
passport.deserializeUser((user: any, done) => done(null, user));

const passportSamlConfig: PassportSamlConfig = {
  callbackUrl: "http://localhost:3000/login/callback",
  issuer: "http://localhost:3000/metadata",
  entryPoint: "http://localhost:18080/simplesaml/saml2/idp/SSOService.php",
  idpCert: idpCert,
  privateKey: signingKey,
  signatureAlgorithm: "sha256",
  digestAlgorithm: "sha256",
  decryptionPvk: decryptionKey,
  disableRequestedAuthnContext: true,
  wantAssertionsSigned: true,
  wantAuthnResponseSigned: false,
  passReqToCallback: true,
}
const samlStrategy = new SamlStrategy(
  passportSamlConfig,
  // ✅ VerifyWithRequest: (req, profile, done)
  (req: express.Request, profile: Profile | null, done: VerifiedCallback) => {
    // you can inspect req here if you want
    return done(null, profile || {});
  },

  // ✅ Logout verify also WithRequest in this overload
  (req: express.Request, profile: Profile | null, done: VerifiedCallback) => {
    return done(null, {});
  }
);

passport.use("saml", samlStrategy);

app.get("/metadata", (_req, res) => {
  res.type("application/xml");
  res.send(samlStrategy.generateServiceProviderMetadata(decryptionCert, signingCert));
});

app.get("/login", passport.authenticate("saml", { failureRedirect: "/login/fail" }));

app.post(
  "/login/callback",
  passport.authenticate("saml", { failureRedirect: "/login/fail" }),
  (_req, res) => res.redirect("/me")
);

app.get("/login/fail", (_req, res) => res.status(401).send("SAML login failed"));

function requireAuth(req: any, res: any, next: any) {
  if (req.isAuthenticated?.()) return next();
  return res.status(401).send("Not authenticated. Go to /login");
}

app.get("/me", requireAuth, (req: any, res) => res.json({ user: req.user }));

app.post("/logout", (req: any, res) => {
  req.logout?.((err: any) => {
    if (err) return res.status(500).send(String(err));
    res.redirect("/");
  });
});

app.get("/", (_req, res) => {
  res.send(`<a href="/login">Login with SAML</a> | <a href="/me">/me</a>`);
});

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

function sanitizeHeaders(headers: Record<string, any>) {
  const redacted = new Set([
    "authorization",
    "cookie",
    "set-cookie",
    "x-amzn-oidc-data",
    "x-amzn-oidc-accesstoken",
  ]);

  const out: Record<string, any> = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k] = redacted.has(k.toLowerCase()) ? "[REDACTED]" : v;
  }
  return out;
}

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

app.get("/debug/login-init", (req, res, next) => {
  // passport.authenticate returns a middleware; we invoke it but override res.redirect
  const middleware = passport.authenticate("saml", { failureRedirect: "/login/fail" });

  const originalRedirect = res.redirect.bind(res);
  (res as any).redirect = (location: string) => {
    // Restore redirect in case anything else uses it later
    (res as any).redirect = originalRedirect;

    res.json({
      wouldRedirectTo: location,
      note:
        "This is the IdP SSO URL with SAMLRequest (and maybe RelayState/signature) generated by the SP.",
    });
    return res;
  };

  middleware(req as any, res as any, next);
});

import { XMLParser } from "fast-xml-parser";

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  removeNSPrefix: false,
});

function safeExtract(obj: any) {
  // These paths vary depending on namespace handling; keep it tolerant.
  const resp =
    obj["samlp:Response"] ||
    obj["Response"] ||
    obj["samlp:ResponseType"] ||
    obj;

  const issuer =
    resp?.["saml:Issuer"]?.["#text"] ||
    resp?.["saml:Issuer"] ||
    resp?.["Issuer"]?.["#text"] ||
    resp?.["Issuer"];

  const destination = resp?.["@_Destination"] || resp?.["@_Destination"];
  const inResponseTo = resp?.["@_InResponseTo"] || resp?.["@_InResponseTo"];

  // Assertion may be encrypted; don't dump it. Just indicate presence.
  const hasAssertion = Boolean(resp?.["saml:Assertion"] || resp?.["Assertion"]);
  const hasEncryptedAssertion = Boolean(
    resp?.["saml:EncryptedAssertion"] ||
      resp?.["EncryptedAssertion"] ||
      resp?.["saml:Assertion"]?.["saml:EncryptedAssertion"]
  );

  return { issuer, destination, inResponseTo, hasAssertion, hasEncryptedAssertion };
}

app.post("/debug/acs", bodyParser.urlencoded({ extended: false }), (req, res) => {
  const samlResponseB64 = (req.body?.SAMLResponse as string | undefined) ?? "";
  const relayState = (req.body?.RelayState as string | undefined) ?? null;

  if (!samlResponseB64) {
    return res.status(400).json({ error: "Missing SAMLResponse" });
  }

  let xml = "";
  try {
    xml = Buffer.from(samlResponseB64, "base64").toString("utf8");
  } catch (e: any) {
    return res.status(400).json({ error: "SAMLResponse was not valid base64", detail: String(e) });
  }

  let parsed: any;
  try {
    parsed = xmlParser.parse(xml);
  } catch (e: any) {
    return res.status(400).json({ error: "Failed to parse SAMLResponse XML", detail: String(e) });
  }

  const extracted = safeExtract(parsed);

  return res.json({
    receivedAt: new Date().toISOString(),
    relayState,
    samlResponse: {
      base64Length: samlResponseB64.length,
      xmlLength: xml.length,
      extracted,
    },
    note:
      "This endpoint does NOT validate signatures or authenticate. It only inspects high-level fields for debugging.",
  });
});

app.get("/debug/routes", (_req, res) => {
  const routes: Array<{ method: string; path: string }> = [];

  // Express internal stack; ok for dev inspection
  (app as any)._router?.stack?.forEach((layer: any) => {
    if (layer?.route?.path && layer?.route?.methods) {
      const methods = Object.keys(layer.route.methods)
        .filter((m) => layer.route.methods[m])
        .map((m) => m.toUpperCase());
      for (const method of methods) routes.push({ method, path: layer.route.path });
    }
  });

  routes.sort((a, b) => (a.path + a.method).localeCompare(b.path + b.method));
  res.json({ routes });
});

app.post("/api/token/from-session", requireAuth, (req: any, res) => {
  const profile = req.user || {};
  const attrs = profile.attributes || {};

  // Pick a stable subject. Your NameID is transient; email/uid is usually better in demos.
  const email = attrs.email || profile.email;
  const uid = attrs.uid || profile.uid;
  const sub = String(email || uid || profile.nameID || "unknown");

  const iat = nowEpoch();
  const tokenPayload = {
    // Standard-ish JWT fields
    iss: JWT_ISSUER,
    aud: JWT_AUDIENCE_PRIMARY,
    sub,
    iat,
    exp: iat + 15 * 60, // 15 min access token

    // Helpful traceability
    jti: `tok_${crypto.randomUUID()}`,
    idp_iss: profile.issuer,                 // SAML Issuer (IdP entityID)
    saml_in_response_to: profile.inResponseTo,
    saml_session_index: profile.sessionIndex,
    saml_nameid: profile.nameID,
    saml_nameid_format: profile.nameIDFormat,
    saml_sp_name_qualifier: profile.spNameQualifier,

    // App-friendly identity claims
    email: email ? String(email) : undefined,
    uid: uid ? String(uid) : undefined,
    groups: safeArray(attrs.eduPersonAffiliation || profile.eduPersonAffiliation),

    // Raw attributes (handy for debugging)
    attributes: attrs,
  };

  // Remove undefined keys (keeps token smaller)
  Object.keys(tokenPayload).forEach((k) => {
    if ((tokenPayload as any)[k] === undefined) delete (tokenPayload as any)[k];
  });

  const accessToken = jwt.sign(tokenPayload, JWT_SECRET, { algorithm: "HS256" });

  res.json({
    tokenType: "Bearer",
    accessToken,
    expiresIn: 15 * 60,
    storageKeySuggested: "access_token_primary",
    note: "Dev endpoint. Client stores in localStorage.",
  });
});

function requireBearer(req: Request, res: Response, next: NextFunction) {
  const auth = req.header("authorization") || "";
  const [scheme, token] = auth.split(" ");
  if (scheme?.toLowerCase() !== "bearer" || !token) {
    return res.status(401).json({ error: "Missing Authorization: Bearer <token>" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ["HS256"],
      issuer: JWT_ISSUER,
    }) as JwtPayload;

    (req as any).accessToken = token;
    (req as any).tokenClaims = decoded;
    return next();
  } catch (e: any) {
    return res.status(401).json({ error: "Invalid token", detail: String(e?.message || e) });
  }
}

app.post("/api/token/exchange", requireBearer, (req: any, res) => {
  const incoming = req.tokenClaims as JwtPayload;

  // Minimal “downscoping” example:
  // - keep identity
  // - change audience
  // - optionally reduce scopes/claims
  const iat = nowEpoch();

  const exchangedPayload = {
    iss: JWT_ISSUER,
    aud: JWT_AUDIENCE_EXCHANGED,
    sub: incoming.sub,
    iat,
    exp: iat + 5 * 60, // shorter-lived downstream token

    jti: `xchg_${crypto.randomUUID()}`,

    // trace: link to original token
    parent_jti: incoming.jti,

    // delegation-style actor claim (toy)
    act: {
      // In real systems this might be the calling client/service identity
      // Here we just stamp something to show the concept.
      sub: "service-a",
    },

    // Keep a subset of identity claims
    email: incoming.email,
    uid: incoming.uid,
    groups: incoming.groups,

    // Example: add/transform “service-specific entitlements”
    // (in real life you'd compute these via DB/policy)
    svc_permissions: ["read:patients", "read:sites"],

    // optionally keep issuer context
    idp_iss: incoming.idp_iss,
  };

  const exchangedToken = jwt.sign(exchangedPayload, JWT_SECRET, { algorithm: "HS256" });

  res.json({
    tokenType: "Bearer",
    exchangedToken,
    expiresIn: 5 * 60,
    storageKeySuggested: "access_token_exchanged",
    note: "Dev-only token exchange emulation (not calling PingAM).",
  });
});

async function mintPrimaryToken() {
  const res = await fetch("/api/token/from-session", { method: "POST" });
  if (!res.ok) throw new Error(await res.text());
  const data = await res.json();
  localStorage.setItem("access_token_primary", data.accessToken);
  return data.accessToken;
}

async function exchangeToken() {
  const primary = localStorage.getItem("access_token_primary");
  if (!primary) throw new Error("No primary token in localStorage");

  const res = await fetch("/api/token/exchange", {
    method: "POST",
    headers: { Authorization: `Bearer ${primary}` },
  });
  if (!res.ok) throw new Error(await res.text());

  const data = await res.json();
  localStorage.setItem("access_token_exchanged", data.exchangedToken);
  return data.exchangedToken;
}

app.get("/api/service-b/resource", requireBearer, (req: any, res) => {
  const claims = req.tokenClaims as JwtPayload;
  if (claims.aud !== JWT_AUDIENCE_EXCHANGED) {
    return res.status(403).json({ error: "Wrong audience for this service" });
  }
  res.json({ ok: true, claims });
});

app.listen(3000, () => console.log("SP listening on http://localhost:3000"));
