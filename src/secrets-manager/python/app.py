import os
import base64
from flask import Flask, request, jsonify

import boto3
from botocore.exceptions import ClientError

app = Flask(__name__)

REGION = os.getenv("AWS_REGION", "eu-west-2")
MODE = os.getenv("MODE", "direct")
ROLE_ARN = os.getenv("ASSUME_ROLE_ARN", "")

def get_session():
    """
    Uses standard AWS credential/provider chain:
    - env vars, shared credentials file, etc.
    - If AWS_PROFILE is set and credentials file is mounted, boto3 will use it.
    """
    profile = os.getenv("AWS_PROFILE")
    if profile:
        return boto3.session.Session(profile_name=profile, region_name=REGION)
    return boto3.session.Session(region_name=REGION)

def get_secrets_client():
    session = get_session()

    if MODE == "assumeRole":
        if not ROLE_ARN:
            raise RuntimeError("ASSUME_ROLE_ARN is required when MODE=assumeRole")

        sts = session.client("sts", region_name=REGION)
        assumed = sts.assume_role(
            RoleArn=ROLE_ARN,
            RoleSessionName="hobby-secrets-lab"
        )
        creds = assumed["Credentials"]

        return boto3.client(
            "secretsmanager",
            region_name=REGION,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

    return session.client("secretsmanager", region_name=REGION)

def get_sts_client():
    session = get_session()

    if MODE == "assumeRole":
        if not ROLE_ARN:
            raise RuntimeError("ASSUME_ROLE_ARN is required when MODE=assumeRole")

        base_sts = session.client("sts", region_name=REGION)
        assumed = base_sts.assume_role(
            RoleArn=ROLE_ARN,
            RoleSessionName="hobby-secrets-lab"
        )
        creds = assumed["Credentials"]

        return boto3.client(
            "sts",
            region_name=REGION,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

    return session.client("sts", region_name=REGION)

@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "python-api"})

@app.get("/whoami")
def whoami():
    sts = get_sts_client()
    ident = sts.get_caller_identity()
    return jsonify({
        "Account": ident.get("Account"),
        "Arn": ident.get("Arn"),
        "UserId": ident.get("UserId"),
        "region": REGION,
        "mode": MODE
    })

@app.get("/secret")
def get_secret():
    """
    GET /secret?secretId=your/secret/name
    Returns either SecretString, or base64-decoded SecretBinary as UTF-8.
    """
    secret_id = request.args.get("secretId")
    if not secret_id:
        return jsonify({"error": "secretId query param is required"}), 400

    sm = get_secrets_client()
    try:
        resp = sm.get_secret_value(SecretId=secret_id)
    except ClientError as e:
        return jsonify({"error": str(e), "secretId": secret_id}), 500

    if "SecretString" in resp:
        return jsonify({"secretId": secret_id, "type": "string", "value": resp["SecretString"]})

    decoded = base64.b64decode(resp["SecretBinary"]).decode("utf-8", errors="replace")
    return jsonify({"secretId": secret_id, "type": "binary", "value": decoded})

if __name__ == "__main__":
    # Flask dev server (fine for a hobby lab)
    app.run(host="0.0.0.0", port=5000, debug=False)
