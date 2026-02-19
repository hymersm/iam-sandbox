export const MAX_LIMIT = 200;

export const escapeFilterValue = (v: string) =>
  v.replace(/[*()\\\0]/g, (c) => {
    switch (c) {
      case "*": return "\\2a";
      case "(": return "\\28";
      case ")": return "\\29";
      case "\\": return "\\5c";
      case "\0": return "\\00";
      default: return c;
    }
  });

export const peopleDn = (uid: string, baseDn: string) => `uid=${uid},ou=People,${baseDn}`;
export const groupDn  = (cn: string, baseDn: string) => `cn=${cn},ou=Groups,${baseDn}`;

export const toArray = (x: any): string[] =>
  Array.isArray(x) ? x.filter(Boolean).map(String) : (x == null ? [] : [String(x)]);

export function mapPerson(entry: any) {
  return {
    dn: String(entry.dn),
    uid: String(entry.uid ?? ""),
    cn: Array.isArray(entry.cn) ? (entry.cn[0] ?? "") : String(entry.cn ?? ""),
    sn: Array.isArray(entry.sn) ? (entry.sn[0] ?? "") : String(entry.sn ?? ""),
    mail: Array.isArray(entry.mail) ? (entry.mail[0] ?? undefined) : (entry.mail ? String(entry.mail) : undefined),
  };
}

export type PeopleListQuery = {
  ldapUrl?: string;
  bindDn?: string;
  bindPassword?: string;
  startTls?: string | boolean;
  baseDn?: string;

  q?: string;
  limit?: string | number;
};

export type CreatePersonBody = {
  ldapUrl?: string;
  bindDn?: string;
  bindPassword?: string;
  startTls?: boolean;
  baseDn: string;

  uid: string;
  cn: string;
  sn: string;
  mail?: string;
  password?: string;
};

export type PatchPersonBody = {
  ldapUrl?: string;
  bindDn?: string;
  bindPassword?: string;
  startTls?: boolean;
  baseDn: string;

  cn?: string;
  sn?: string;
  mail?: string | null;
  password?: string;
};