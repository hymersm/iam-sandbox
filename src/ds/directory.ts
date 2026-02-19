import { Client, Change, Attribute } from "ldapts";

export type DirectoryConnectionConfig = {
  ldapUrl: string;               // ldap://host:389 or ldaps://host:636
  bindDn?: string;
  bindPassword?: string;
  startTls?: boolean;            // only valid when ldapUrl starts with ldap://
  timeoutMs?: number;
  connectTimeoutMs?: number;
};

export class DirectoryClient {
  private client: Client;
  private cfg: DirectoryConnectionConfig;   

  constructor(cfg: DirectoryConnectionConfig) {
    this.cfg = cfg;
    this.client = new Client({
      url: cfg.ldapUrl,
      timeout: cfg.timeoutMs ?? 10_000,
      connectTimeout: cfg.connectTimeoutMs ?? 10_000,
    });
  }

  async connectAndBind() {
    // StartTLS only applies to ldap:// (not ldaps://)
    if (this.cfg.startTls) {
      if (!this.cfg.ldapUrl.startsWith("ldap://")) {
        throw new Error("startTls=true is only valid with ldap:// URLs");
      }
      // ldapts supports this; will throw if server doesn't support StartTLS
      await this.client.startTLS();
    }

    if (this.cfg.bindDn) {
      await this.client.bind(this.cfg.bindDn, this.cfg.bindPassword ?? "");
    }
  }

  async search(baseDn: string, opts: Parameters<Client["search"]>[1]) {
    return this.client.search(baseDn, opts);
  }

  async add(dn: string, entry: Record<string, any>) {
    return this.client.add(dn, entry);
  }

  async modify(dn: string, changes: Change[]) {
    return this.client.modify(dn, changes);
  }

  async del(dn: string) {
    return this.client.del(dn);
  }

  async modifyDN(dn: string, newRdn: string) {
    return this.client.modifyDN(dn, newRdn);
  }

  async close() {
    try { await this.client.unbind(); } catch {}
  }
}

// helpers for changes
export const replace = (type: string, values: string[]) => {
    return new Change({ operation: "replace", modification: new Attribute({ type, values }) } );
} 

export const addVals = (type: string, values: string[]) => {
  new Change({ operation: "add", modification: new Attribute({ type, values }) } );
}

export const delVals = (type: string, values: string[]) => {
  new Change({ operation: "delete", modification: new Attribute({ type, values }) } );
}