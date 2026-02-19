import express from "express";
import bodyParser from "body-parser";
import * as utils from "./utils";
import * as user from "./user";
import { Client } from "ldapts";
import type { Request, Response } from "express";
import tls from "node:tls";
import { DirectoryClient, DirectoryConnectionConfig, replace } from "./directory";

const LDAP_URL="ldap://localhost:389";
const LDAP_BIND_DN="cn=admin,dc=example,dc=org";
const LDAP_BIND_PASSWORD="adminpassword";

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());

// --- Endpoint: GET /directory/info ---
app.get("/directory/info", async (req: Request, res: Response) => {
  // Prefer env config (best for services); allow override via query for quick lab testing.
  const ldapUrl = String(req.query.ldapUrl ?? LDAP_URL ?? "ldap://localhost:389");

  // Optional bind: RootDSE is usually readable anonymously in many servers,
  // but some lock it down; support bind creds via env.
  const bindDn = String(req.query.bindDn ?? LDAP_BIND_DN ?? "");
  const bindPassword = String(req.query.bindPassword ?? LDAP_BIND_PASSWORD ?? "");

  try {
    const info = await utils.fetchDirectoryInfo(
      ldapUrl,
      bindDn || undefined,
      bindPassword || undefined
    );

    res.json(info);
  } catch (err: any) {
    res.status(502).json({
      error: "DIRECTORY_INTROSPECTION_FAILED",
      message: err?.message ?? String(err),
      ldapUrl,
    });
  }
});

app.get("/directory/capabilities", async (req: Request, res: Response) => {
  // Prefer env config (best for services); allow override via query for quick lab testing.
  const ldapUrl = String(req.query.ldapUrl ?? LDAP_URL ?? "ldap://localhost:389");

  // Optional bind: RootDSE is usually readable anonymously in many servers,
  // but some lock it down; support bind creds via env.
  const bindDn = String(req.query.bindDn ?? LDAP_BIND_DN ?? "");
  const bindPassword = String(req.query.bindPassword ?? LDAP_BIND_PASSWORD ?? "");

  try {
    const info = await utils.fetchDirectoryInfo(
      ldapUrl,
      bindDn || undefined,
      bindPassword || undefined
    );

    res.json({
      ...info,
      controls: utils.describeOids(info.supportedControls, "control"),
      extensions: utils.describeOids(info.supportedExtensions, "extension"),
      features: info.raw?.supportedFeatures
        ? utils.describeOids(info.raw.supportedFeatures as string[], "feature")
        : [],
    });
  } catch (err: any) {
    res.status(502).json({
      error: "DIRECTORY_CAPABILITIES_FAILED",
      message: err?.message ?? String(err),
    });
  }
});

const WHOAMI_OID = "1.3.6.1.4.1.4203.1.11.3";

app.get("/directory/whoami", async (req: Request, res: Response) => {
  const ldapUrl = String(req.query.ldapUrl ?? LDAP_URL ?? "ldap://localhost:389");
  const bindDn = String(req.query.bindDn ?? LDAP_BIND_DN ?? "");
  const bindPassword = String(req.query.bindPassword ?? LDAP_BIND_PASSWORD ?? "");

  const client = new Client({ url: ldapUrl, timeout: 10_000, connectTimeout: 10_000 });

  try {
    const info = await utils.fetchDirectoryInfo(
      ldapUrl,
      bindDn || undefined,
      bindPassword || undefined
    );
    const supportsWhoAmI = info.supportedExtensions.includes(WHOAMI_OID);

    if (!supportsWhoAmI) {
      return res.status(501).json({
        supported: false,
        oid: WHOAMI_OID,
        message: "Server does not advertise Who Am I? extended operation support.",
      });
    }

    if (!bindDn || !bindPassword) {
      return res.status(400).json({
        error: "BAD_REQUEST",
        message: "bindDn and bindPassword are required for whoami",
      });
    }

    await client.bind(bindDn, bindPassword);

    const { value } = await client.exop(WHOAMI_OID);

    return res.json({
      supported: true,
      oid: WHOAMI_OID,
      authzId: value ?? null,
    });
  } catch (err: any) {
    return res.status(502).json({
      error: "DIRECTORY_WHOAMI_FAILED",
      message: err?.message ?? String(err),
      ldapUrl,
    });
  } finally {
    try {
      await client.unbind();
    } catch {
      /* ignore */
    }
  }
});

/*
curl -s http://localhost:3001/directory/auth/test \
  -H "content-type: application/json" \
  -d '{
    "bindDn": "cn=admin,dc=example,dc=org",
    "bindPassword": "adminpassword"
  }' | jq .
*/
app.post("/directory/auth/test", async (req: Request, res: Response) => {
  const body = req.body as Partial<utils.AuthTestBody>;

  const ldapUrl = String(body.ldapUrl ?? LDAP_URL ?? "ldap://localhost:389");
  const bindDn = String(body.bindDn ?? "");
  const bindPassword = String(body.bindPassword ?? "");

  if (!bindDn || !bindPassword) {
    return res.status(400).json({
      error: "BAD_REQUEST",
      message: "bindDn and bindPassword are required",
    });
  }

  const client = new Client({ url: ldapUrl, timeout: 10_000, connectTimeout: 10_000 });

  try {
    // Bind test
    await client.bind(bindDn, bindPassword);

    // Check if WhoAmI is supported (Root DSE)
    const info = await utils.fetchDirectoryInfo(ldapUrl, bindDn, bindPassword);
    const supportedWhoAmI = info.supportedExtensions.includes(WHOAMI_OID);

    let authzId: string | null = null;
    if (supportedWhoAmI) {
      const { value } = await client.exop(WHOAMI_OID);
      authzId = value ?? null;
    }

    return res.json({
      ok: true,
      supportedWhoAmI,
      authzId,
    });
  } catch (err: any) {
    // Common LDAP bind failures are typically invalidCredentials, etc.
    return res.status(401).json({
      ok: false,
      error: "AUTH_TEST_FAILED",
      message: err?.message ?? String(err),
    });
  } finally {
    try {
      await client.unbind();
    } catch {
      /* ignore */
    }
  }
});

app.get("/directory/schema", async (req: Request, res: Response) => {
  const ldapUrl = String(req.query.ldapUrl ?? LDAP_URL ?? "ldap://localhost:389");
  const bindDn = String(req.query.bindDn ?? LDAP_BIND_DN ?? "");
  const bindPassword = String(req.query.bindPassword ?? LDAP_BIND_PASSWORD ?? "");

  const q = String(req.query.q ?? "").trim().toLowerCase();

  try {
    const schema = await utils.fetchSchemaSummary(
      ldapUrl,
      bindDn || undefined,
      bindPassword || undefined
    );

    // Optional filter by name
    if (q) {
      schema.objectClasses = schema.objectClasses.filter((o) => o.name.toLowerCase().includes(q));
      schema.attributeTypes = schema.attributeTypes.filter((a) => a.name.toLowerCase().includes(q));
    }

    res.json(schema);
  } catch (err: any) {
    res.status(502).json({
      error: "DIRECTORY_SCHEMA_FAILED",
      message: err?.message ?? String(err),
      ldapUrl,
    });
  }
});

type SearchBody = {
  ldapUrl?: string;
  bindDn?: string;
  bindPassword?: string;

  baseDn: string;
  scope?: "base" | "one" | "sub";
  filter: string;
  attributes?: string[];

  sizeLimit?: number;  // max entries
  timeLimitSeconds?: number; // server-side time limit
};

const DEFAULT_ATTRS = ["dn", "cn", "sn", "uid", "mail", "ou", "memberOf"];

function sanitizeAttributes(attrs?: string[]): string[] {
  const a = (attrs?.length ? attrs : DEFAULT_ATTRS).map(String);
  const blocked = new Set(["userpassword", "olcrootpw"]);
  return a.filter(x => x && !blocked.has(x.toLowerCase()));
}


/*
curl -s http://localhost:3001/directory/search \
  -H "content-type: application/json" \
  -d '{
    "baseDn": "dc=example,dc=org",
    "scope": "sub",
    "filter": "(objectClass=*)",
    "attributes": ["dn","objectClass","cn","sn","uid","mail"],
    "sizeLimit": 50
  }' | jq .
*/
app.post("/directory/search", async (req: Request, res: Response) => {
  const body = req.body as Partial<SearchBody>;

  const ldapUrl = String(body.ldapUrl ?? LDAP_URL ?? "ldap://localhost:389");
  const bindDn = String(body.bindDn ?? LDAP_BIND_DN ?? "");
  const bindPassword = String(body.bindPassword ?? LDAP_BIND_PASSWORD ?? "");

  const baseDn = String(body.baseDn ?? "");
  const scope = (body.scope ?? "sub") as "base" | "one" | "sub";
  const filter = String(body.filter ?? "").trim();

  if (!baseDn || !filter) {
    return res.status(400).json({
      error: "BAD_REQUEST",
      message: "baseDn and filter are required",
    });
  }

  // Guardrails
  const sizeLimit = Math.min(Math.max(Number(body.sizeLimit ?? 50), 1), 200);
  const timeLimitSeconds = Math.min(Math.max(Number(body.timeLimitSeconds ?? 5), 1), 15);
  const attributes = sanitizeAttributes(body.attributes);

  const client = new Client({ url: ldapUrl, timeout: 10_000, connectTimeout: 10_000 });

  const start = Date.now();
  try {
    await client.bind(bindDn, bindPassword);

    const result = await client.search(baseDn, {
      scope,
      filter,
      attributes,
      sizeLimit,
      timeLimit: timeLimitSeconds,
      // typesOnly: false,
    });

    res.json({
      ok: true,
      tookMs: Date.now() - start,
      count: result.searchEntries.length,
      entries: result.searchEntries,
    });
  } catch (err: any) {
    res.status(502).json({
      ok: false,
      error: "DIRECTORY_SEARCH_FAILED",
      message: err?.message ?? String(err),
      tookMs: Date.now() - start,
    });
  } finally {
    try { await client.unbind(); } catch {}
  }
});

/*
command
curl -X POST http://localhost:3001/directory/auth/test \
  -H 'content-type: application/json' \
  -d '{
    "ldapUrl": "ldap://localhost:389",
    "startTls": false,
    "bindDn": "cn=admin,dc=example,dc=org",          
    "bindPassword": "adminpassword"
  }'

response  
{"ok":true,"ldapUrl":"ldap://localhost:389","bindDn":"cn=admin,dc=example,dc=org","startTls":false}
*/
app.post("/directory/auth/test2", async (req, res) => {
  const body = req.body as utils.AuthTestBody;

  const ldapUrl = String(body.ldapUrl ?? process.env.LDAP_URL ?? "ldap://localhost:389");
  const bindDn = String(body.bindDn ?? "");
  const bindPassword = String(body.bindPassword ?? "");

  if (!bindDn || !bindPassword) {
    return res.status(400).json({
      error: "MISSING_CREDENTIALS",
      message: "bindDn and bindPassword are required",
    });
  }

  const tlsOptions: tls.ConnectionOptions | undefined =
    body.allowInsecureTLS || body.caCertPem
      ? {
          ...(body.allowInsecureTLS ? { rejectUnauthorized: false } : {}),
          ...(body.caCertPem ? { ca: [body.caCertPem] } : {}),
        }
      : undefined;

  const dcc: DirectoryConnectionConfig = {
    ldapUrl: ldapUrl,
    startTls: Boolean(body.startTls),
    bindDn,
    bindPassword,
  }

  const client = new DirectoryClient(dcc);

  try {
    await client.connectAndBind();

    // If bind succeeded, we’re good.
    res.json({
      ok: true,
      ldapUrl,
      bindDn,
      startTls: Boolean(body.startTls),
    });
  } catch (err: any) {
    res.status(502).json({
      error: "DIRECTORY_BIND_FAILED",
      message: err?.message ?? String(err),
      ldapUrl,
      bindDn,
      startTls: Boolean(body.startTls),
    });
  } finally {
    await client.close();
  }
});

/*
visited: http://localhost:3001/directory/base-dn/validate?baseDn=dc=example,dc=org
response: 
{
  "ok": true,
  "ldapUrl": "ldap://localhost:389",
  "baseDn": "dc=example,dc=org",
  "startTls": false,
  "sample": {
    "dn": "dc=example,dc=org",
    "objectClass": [
      "top",
      "dcObject",
      "organization"
    ]
  }
}


*/
app.get("/directory/base-dn/validate", async (req, res) => {
  // Prefer env config; allow override via query for lab testing.
  const ldapUrl = String(req.query.ldapUrl ?? LDAP_URL ?? "ldap://localhost:389");

  // Base DN can come from env or query override
  const baseDn = String(req.query.baseDn ?? "");

  // Optional bind (same pattern as /directory/info)
  const bindDn = String(req.query.bindDn ?? LDAP_BIND_DN ?? "");
  const bindPassword = String(req.query.bindPassword ?? LDAP_BIND_PASSWORD ?? "");

  // Optional StartTLS + TLS flags (lab)
  const startTls = String(req.query.startTls ?? "") === "true";
  const allowInsecureTLS = String(req.query.allowInsecureTLS ?? "") === "true";

  if (!baseDn) {
    return res.status(400).json({
      error: "MISSING_BASE_DN",
      message: "baseDn (or LDAP_BASE_DN) is required",
      ldapUrl,
    });
  }

  const tlsOptions: tls.ConnectionOptions | undefined = allowInsecureTLS
    ? { rejectUnauthorized: false }
    : undefined;

  const client = new DirectoryClient({
    ldapUrl: ldapUrl,
    startTls,
    bindDn: bindDn,
    bindPassword: bindPassword,
  });

  try {
    await client.connectAndBind();

    const result = await client.search(baseDn, {
      scope: "base",
      filter: "(objectClass=*)",
      attributes: ["dn", "objectClass"],
      sizeLimit: 1,
      paged: false,
    });

    const exists = Array.isArray(result?.searchEntries) && result.searchEntries.length > 0;

    if (!exists) {
      // Rare but possible depending on server behavior
      return res.status(404).json({
        ok: false,
        error: "BASE_DN_NOT_FOUND",
        message: "Base DN did not return any entries",
        ldapUrl,
        baseDn,
        startTls,
      });
    }

    res.json({
      ok: true,
      ldapUrl,
      baseDn,
      startTls,
      // Helpful for debugging / evidence
      sample: result.searchEntries[0],
    });
  } catch (err: any) {
    // Many LDAP servers throw “No Such Object” for invalid base DN;
    // ldapts error shapes vary by server, so keep this conservative.
    res.status(502).json({
      ok: false,
      error: "BASE_DN_VALIDATE_FAILED",
      message: err?.message ?? String(err),
      ldapUrl,
      baseDn,
      startTls,
    });
  } finally {
    await client.close();
  }
});

app.get("/directory/people", async (req: Request, res: Response) => {
  const q = String((req.query as any).q ?? "").trim();
  const limit = Math.min(Math.max(Number((req.query as any).limit ?? 50), 1), user.MAX_LIMIT);

  const ldapUrl = String((req.query as any).ldapUrl ?? LDAP_URL ?? "ldap://localhost:389");
  const bindDn = String((req.query as any).bindDn ?? LDAP_BIND_DN ?? "");
  const bindPassword = String((req.query as any).bindPassword ?? LDAP_BIND_PASSWORD ?? "");
  const baseDn = String((req.query as any).baseDn ?? "dc=example,dc=org");
  const startTls = String((req.query as any).startTls ?? "false") === "true";

  const filter = q
    ? `(&(objectClass=inetOrgPerson)(|(uid=*${user.escapeFilterValue(q)}*)(cn=*${user.escapeFilterValue(q)}*)(sn=*${user.escapeFilterValue(q)}*)(mail=*${user.escapeFilterValue(q)}*)))`
    : `(objectClass=inetOrgPerson)`;

  const client = new DirectoryClient({
    ldapUrl,
    bindDn: bindDn,
    bindPassword: bindPassword,
    startTls,
  });

  const start = Date.now();
  try {
    await client.connectAndBind();

    const result = await client.search(`ou=People,${baseDn}`, {
      scope: "sub",
      filter,
      attributes: ["dn", "uid", "cn", "sn", "mail"],
      sizeLimit: limit,
      timeLimit: 5,
    });

    res.json({
      ok: true,
      tookMs: Date.now() - start,
      count: result.searchEntries.length,
      people: result.searchEntries.map(user.mapPerson),
    });
  } catch (err: any) {
    res.status(502).json({
      ok: false,
      error: "DIRECTORY_PEOPLE_LIST_FAILED",
      message: err?.message ?? String(err),
      tookMs: Date.now() - start,
    });
  } finally {
    await client.close();
  }
});

app.get("/directory/people/:uid", async (req: Request, res: Response) => {
  const uid = String(req.params.uid).trim();
  if (!uid) return res.status(400).json({ error: "BAD_REQUEST", message: "uid required" });

  const ldapUrl = String(req.query.ldapUrl ?? LDAP_URL ?? "ldap://localhost:389");
  const bindDn = String(req.query.bindDn ?? LDAP_BIND_DN ?? "");
  const bindPassword = String(req.query.bindPassword ?? LDAP_BIND_PASSWORD ?? "");
  const baseDn = String(req.query.baseDn ?? "dc=example,dc=org");
  const startTls = String(req.query.startTls ?? "false") === "true";

  const dn = user.peopleDn(uid, baseDn);

  const client = new DirectoryClient({ ldapUrl, bindDn: bindDn, bindPassword: bindPassword, startTls });
  const start = Date.now();
  try {
    await client.connectAndBind();

    const r = await client.search(dn, {
      scope: "base",
      filter: "(objectClass=*)",
      attributes: ["dn", "uid", "cn", "sn", "mail"],
      sizeLimit: 1,
      timeLimit: 5,
    });

    const entry = r.searchEntries[0];
    if (!entry) return res.status(404).json({ ok: false, error: "NOT_FOUND", message: "Person not found", uid });

    res.json({ ok: true, tookMs: Date.now() - start, person: user.mapPerson(entry) });
  } catch (err: any) {
    res.status(502).json({
      ok: false,
      error: "DIRECTORY_PERSON_READ_FAILED",
      message: err?.message ?? String(err),
      tookMs: Date.now() - start,
    });
  } finally {
    await client.close();
  }
});

app.post("/directory/people", async (req: Request, res: Response) => {
  const body = req.body as Partial<user.CreatePersonBody>;

  const ldapUrl = String(body.ldapUrl ?? LDAP_URL ?? "ldap://localhost:389");
  const bindDn = String(body.bindDn ?? LDAP_BIND_DN ?? "");
  const bindPassword = String(body.bindPassword ?? LDAP_BIND_PASSWORD ?? "");
  const baseDn = String(body.baseDn ?? "");
  const startTls = Boolean(body.startTls ?? false);

  const uid = String(body.uid ?? "").trim();
  const cn = String(body.cn ?? "").trim();
  const sn = String(body.sn ?? "").trim();
  const mail = body.mail ? String(body.mail).trim() : undefined;
  const password = body.password ? String(body.password) : undefined;

  if (!baseDn || !uid || !cn || !sn) {
    return res.status(400).json({
      error: "BAD_REQUEST",
      message: "baseDn, uid, cn, sn are required",
    });
  }

  const dn = user.peopleDn(uid, baseDn);

  const client = new DirectoryClient({ ldapUrl, bindDn: bindDn, bindPassword: bindPassword, startTls });
  const start = Date.now();
  try {
    await client.connectAndBind();

    await client.add(dn, {
      objectClass: ["top", "person", "organizationalPerson", "inetOrgPerson"],
      uid,
      cn,
      sn,
      ...(mail ? { mail } : {}),
      ...(password ? { userPassword: password } : {}),
    });

    res.status(201).json({ ok: true, tookMs: Date.now() - start, dn, uid });
  } catch (err: any) {
    res.status(502).json({
      ok: false,
      error: "DIRECTORY_PERSON_CREATE_FAILED",
      message: err?.message ?? String(err),
      tookMs: Date.now() - start,
      dn,
      uid,
    });
  } finally {
    await client.close();
  }
});

app.patch("/directory/people/:uid", async (req: Request, res: Response) => {
  const uid = String(req.params.uid).trim();
  const body = req.body as Partial<user.PatchPersonBody>;

  const ldapUrl = String(body.ldapUrl ?? LDAP_URL ?? "ldap://localhost:389");
  const bindDn = String(body.bindDn ?? LDAP_BIND_DN ?? "");
  const bindPassword = String(body.bindPassword ?? LDAP_BIND_PASSWORD ?? "");
  const baseDn = String(body.baseDn ?? "");
  const startTls = Boolean(body.startTls ?? false);

  if (!baseDn || !uid) {
    return res.status(400).json({ error: "BAD_REQUEST", message: "baseDn and uid are required" });
  }

  const dn = user.peopleDn(uid, baseDn);

  const changes = [];
  if (body.cn != null) changes.push(replace("cn", [String(body.cn).trim()]));
  if (body.sn != null) changes.push(replace("sn", [String(body.sn).trim()]));
  if (body.mail !== undefined) {
    // allow null to clear
    changes.push(replace("mail", body.mail === null ? [] : [String(body.mail).trim()]));
  }
  if (body.password != null) changes.push(replace("userPassword", [String(body.password)]));

  if (changes.length === 0) {
    return res.status(400).json({ error: "BAD_REQUEST", message: "No fields to update" });
  }

  const client = new DirectoryClient({ ldapUrl, bindDn: bindDn, bindPassword: bindPassword, startTls });
  const start = Date.now();
  try {
    await client.connectAndBind();
    await client.modify(dn, changes);
    res.json({ ok: true, tookMs: Date.now() - start, dn, uid });
  } catch (err: any) {
    res.status(502).json({
      ok: false,
      error: "DIRECTORY_PERSON_UPDATE_FAILED",
      message: err?.message ?? String(err),
      tookMs: Date.now() - start,
      dn,
      uid,
    });
  } finally {
    await client.close();
  }
});

app.delete("/directory/people/:uid", async (req: Request, res: Response) => {
  const uid = String(req.params.uid).trim();

  const ldapUrl = String(req.query.ldapUrl ?? LDAP_URL ?? "ldap://localhost:389");
  const bindDn = String(req.query.bindDn ?? LDAP_BIND_DN ?? "");
  const bindPassword = String(req.query.bindPassword ?? LDAP_BIND_PASSWORD ?? "");
  const baseDn = String(req.query.baseDn ?? "dc=example,dc=org");
  const startTls = String(req.query.startTls ?? "false") === "true";

  const dn = user.peopleDn(uid, baseDn);

  const client = new DirectoryClient({ ldapUrl, bindDn: bindDn, bindPassword: bindPassword, startTls });
  const start = Date.now();
  try {
    await client.connectAndBind();
    await client.del(dn);
    res.json({ ok: true, tookMs: Date.now() - start, dn, uid });
  } catch (err: any) {
    res.status(502).json({
      ok: false,
      error: "DIRECTORY_PERSON_DELETE_FAILED",
      message: err?.message ?? String(err),
      tookMs: Date.now() - start,
      dn,
      uid,
    });
  } finally {
    await client.close();
  }
});

app.listen(3001, () => console.log("DS discovery listening on http://localhost:3001"));