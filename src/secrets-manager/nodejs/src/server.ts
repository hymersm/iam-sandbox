import express from "express";
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { fromTemporaryCredentials } from "@aws-sdk/credential-providers";

const app = express();

const region = process.env.AWS_REGION || "eu-west-2";
const mode = process.env.MODE || "direct";
const roleArn = process.env.ASSUME_ROLE_ARN || "";

function awsCredentialsIfAssumeRole() {
  if (mode !== "assumeRole") return undefined;
  if (!roleArn) throw new Error("ASSUME_ROLE_ARN is required when MODE=assumeRole");

  // Base credentials come from the default chain (env vars, /root/.aws, etc.).
  return fromTemporaryCredentials({
    params: {
      RoleArn: roleArn,
      RoleSessionName: "hobby-secrets-lab",
    },
    clientConfig: { region },
  });
}

function secretsClient() {
  return new SecretsManagerClient({
    region,
    credentials: awsCredentialsIfAssumeRole(),
  });
}

function stsClient() {
  return new STSClient({
    region,
    credentials: awsCredentialsIfAssumeRole(),
  });
}

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "node-api" });
});

app.get("/whoami", async (_req, res) => {
  try {
    const sts = stsClient();
    const ident = await sts.send(new GetCallerIdentityCommand({}));
    res.json({
      Account: ident.Account,
      Arn: ident.Arn,
      UserId: ident.UserId,
      region,
      mode,
    });
  } catch (e: any) {
    res.status(500).json({ error: String(e?.message ?? e) });
  }
});

app.get("/secret", async (req, res) => {
  const secretId = String(req.query.secretId || "");
  if (!secretId) return res.status(400).json({ error: "secretId query param is required" });

  try {
    const sm = secretsClient();
    const resp = await sm.send(new GetSecretValueCommand({ SecretId: secretId }));
    const value =
      resp.SecretString ??
      (resp.SecretBinary ? Buffer.from(resp.SecretBinary as any).toString("utf-8") : null);

    if (value === null) return res.status(500).json({ error: "Secret had no SecretString/SecretBinary" });

    res.json({ secretId, type: resp.SecretString ? "string" : "binary", value });
  } catch (e: any) {
    res.status(500).json({ error: String(e?.message ?? e), secretId });
  }
});

app.listen(3000, () => {
  // eslint-disable-next-line no-console
  console.log(`node-api listening on :3000 (region=${region}, mode=${mode})`);
});
