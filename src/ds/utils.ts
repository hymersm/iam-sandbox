import { Client } from "ldapts";

export type SchemaSummary = {
  subschemaSubentry: string | null;
  objectClasses: Array<{
    name: string;
    sup: string[];
    kind: "ABSTRACT" | "STRUCTURAL" | "AUXILIARY" | "UNKNOWN";
    must: string[];
    may: string[];
  }>;
  attributeTypes: Array<{
    name: string;
    sup: string[];
    syntax: string | null;
    singleValue: boolean;
    equality: string | null;
    ordering: string | null;
    substr: string | null;
  }>;
};

// Very lightweight parser: enough to explore, not a full RFC4512 parser
function parseSchemaNames(def: string): (string|undefined)[] {
  const m = def.match(/\bNAME\s+\(?\s*'([^']+)'/);
  if (m?.[1]) return [m[1]];

  const mm = def.match(/\bNAME\s+\(\s*([^)]+)\)/);
  if (!mm?.[1]) return [];
  return Array.from(mm[1].matchAll(/'([^']+)'/g)).map(x => x[1]);
}

function parseList(def: string, key: string): string[] {
  // matches: KEY ( a $ b $ c )  OR KEY a
  const reList = new RegExp(`\\b${key}\\s+\\(\\s*([^\\)]+)\\)`, "i");
  const reSingle = new RegExp(`\\b${key}\\s+([^\\s\\)]+)`, "i");

  const ml = def.match(reList);
  const raw = ml?.[1] ?? def.match(reSingle)?.[1] ?? "";
  if (!raw) return [];

  return raw
    .split(/\s*\$\s*|\s+/)
    .map(s => s.trim())
    .filter(Boolean)
    .map(s => s.replace(/^'|'$/g, ""));
}

function parseFlag(def: string, key: string): boolean {
  return new RegExp(`\\b${key}\\b`, "i").test(def);
}

function parseToken(def: string, key: string): string | null {
  const re = new RegExp(`\\b${key}\\s+([^\\s\\)]+)`, "i");
  const m = def.match(re);
  return m?.[1]?.replace(/^'|'$/g, "") ?? null;
}

function parseKind(def: string): SchemaSummary["objectClasses"][number]["kind"] {
  if (/\bABSTRACT\b/i.test(def)) return "ABSTRACT";
  if (/\bSTRUCTURAL\b/i.test(def)) return "STRUCTURAL";
  if (/\bAUXILIARY\b/i.test(def)) return "AUXILIARY";
  return "UNKNOWN";
}

export async function fetchSchemaSummary(
  ldapUrl: string,
  bindDn?: string,
  bindPassword?: string,
  opts?: { maxObjectClasses?: number; maxAttributeTypes?: number }
): Promise<SchemaSummary> {
  const client = new Client({ url: ldapUrl, timeout: 10_000, connectTimeout: 10_000 });

  const maxObjectClasses = opts?.maxObjectClasses ?? 500;
  const maxAttributeTypes = opts?.maxAttributeTypes ?? 1000;

  try {
    if (bindDn && bindPassword) await client.bind(bindDn, bindPassword);

    // Root DSE: fetch subschemaSubentry
    const rootRes = await client.search("", {
      scope: "base",
      filter: "(objectClass=*)",
      attributes: ["subschemaSubentry"],
    });

    const root = (rootRes.searchEntries?.[0] ?? {}) as Record<string, unknown>;
    const subschemaSubentry =
      (Array.isArray(root.subschemaSubentry) ? root.subschemaSubentry[0] : root.subschemaSubentry) as string | undefined;

    if (!subschemaSubentry) {
      return { subschemaSubentry: null, objectClasses: [], attributeTypes: [] };
    }

    const schemaRes = await client.search(subschemaSubentry, {
      scope: "base",
      filter: "(objectClass=*)",
      attributes: ["objectClasses", "attributeTypes"],
    });

    const schemaEntry = (schemaRes.searchEntries?.[0] ?? {}) as Record<string, unknown>;
    const rawOCs = (Array.isArray(schemaEntry.objectClasses) ? schemaEntry.objectClasses : schemaEntry.objectClasses ? [schemaEntry.objectClasses] : []) as string[];
    const rawATs = (Array.isArray(schemaEntry.attributeTypes) ? schemaEntry.attributeTypes : schemaEntry.attributeTypes ? [schemaEntry.attributeTypes] : []) as string[];

    const objectClasses = rawOCs.slice(0, maxObjectClasses).map((def) => {
      const names = parseSchemaNames(def);
      return {
        name: names[0] ?? "(unnamed)",
        sup: parseList(def, "SUP"),
        kind: parseKind(def),
        must: parseList(def, "MUST"),
        may: parseList(def, "MAY"),
      };
    });

    const attributeTypes = rawATs.slice(0, maxAttributeTypes).map((def) => {
      const names = parseSchemaNames(def);
      return {
        name: names[0] ?? "(unnamed)",
        sup: parseList(def, "SUP"),
        syntax: parseToken(def, "SYNTAX"),
        singleValue: parseFlag(def, "SINGLE-VALUE"),
        equality: parseToken(def, "EQUALITY"),
        ordering: parseToken(def, "ORDERING"),
        substr: parseToken(def, "SUBSTR"),
      };
    });

    return { subschemaSubentry, objectClasses, attributeTypes };
  } finally {
    try { await client.unbind(); } catch {}
  }
}


export type OidDescriptor = {
  oid: string;
  name: string | null;
  kind: "control" | "extension" | "feature";
  note?: string;
};

export type AuthTestBody = {
  ldapUrl?: string;            // optional override
  bindDn: string;
  bindPassword: string;

  // Optional lab controls
  startTls?: boolean;          // only for ldap://
  allowInsecureTLS?: boolean;  // rejectUnauthorized=false
  caCertPem?: string;          // PEM CA string (optional)
};

export type DirectoryInfo = {
  baseDn: string | null;
  namingContexts: string[];
  supportedLDAPVersions: number[];
  supportedControls: string[];
  supportedExtensions: string[];
  raw?: Record<string, unknown>;
};

export const OID_LABELS: Record<string, OidDescriptor> = {
  // --- Extensions ---
  // LDAP "Who am I?" extended op (RFC 4532)
  "1.3.6.1.4.1.4203.1.11.3": {
    oid: "1.3.6.1.4.1.4203.1.11.3",
    name: "Who Am I? (RFC 4532)",
    kind: "extension",
  },
  // LDAP Password Modify extended op (RFC 3062)
  "1.3.6.1.4.1.4203.1.11.1": {
    oid: "1.3.6.1.4.1.4203.1.11.1",
    name: "Password Modify (RFC 3062)",
    kind: "extension",
  },
  // LDAP Cancel extended op (RFC 3909)
  "1.3.6.1.1.8": {
    oid: "1.3.6.1.1.8",
    name: "Cancel (RFC 3909)",
    kind: "extension",
  },
};

export function describeOids(
  oids: string[],
  kind: OidDescriptor["kind"]
): OidDescriptor[] {
  return oids.map((oid) => {
    const known = OID_LABELS[oid];
    return known
      ? known
      : { oid, name: null, kind };
  });
}

export function asStringArray(value: unknown): string[] {
  if (!value) return [];
  if (Array.isArray(value)) return value.map(String).filter(Boolean);
  return [String(value)].filter(Boolean);
}

export function asNumberArray(value: unknown): number[] {
  return asStringArray(value)
    .map((v) => Number(v))
    .filter((n) => Number.isFinite(n));
}

/**
 * Root DSE (RFC 4512) is queried with:
 * - baseDN: ""
 * - scope: "base"
 * - filter: "(objectClass=*)"
 * It returns server capabilities such as namingContexts, supportedLDAPVersion, etc.
 */
export async function fetchDirectoryInfo(ldapUrl: string, bindDn?: string, bindPassword?: string): Promise<DirectoryInfo> {
  const client = new Client({
    url: ldapUrl,
    timeout: 10_000,
    connectTimeout: 10_000,
  });

  try {
    if (bindDn && bindPassword) {
      await client.bind(bindDn, bindPassword);
    }

    const { searchEntries } = await client.search("", {
      scope: "base",
      filter: "(objectClass=*)",
      attributes: [
        "defaultNamingContext",
        "namingContexts",
        "supportedLDAPVersion",
        "supportedControl",
        "supportedExtension",
        "supportedFeatures",
        "vendorName",
        "vendorVersion",
      ],
    });

    const root = (searchEntries?.[0] ?? {}) as Record<string, unknown>;

    const namingContexts = asStringArray(root.namingContexts);
    const baseDn =
      (asStringArray(root.defaultNamingContext)[0] ?? null) ||
      (namingContexts[0] ?? null);

    return {
      baseDn,
      namingContexts,
      supportedLDAPVersions: asNumberArray(root.supportedLDAPVersion),
      supportedControls: asStringArray(root.supportedControl),
      supportedExtensions: asStringArray(root.supportedExtension),
      // Optional: include some extra metadata to help debugging/introspection
      raw: {
        vendorName: asStringArray(root.vendorName)[0] ?? null,
        vendorVersion: asStringArray(root.vendorVersion)[0] ?? null,
        supportedFeatures: asStringArray(root.supportedFeatures),
      },
    };
  } finally {
    // ldapts throws if you unbind when not bound sometimes; guard it.
    try {
      await client.unbind();
    } catch {
      // ignore
    }
  }
}
