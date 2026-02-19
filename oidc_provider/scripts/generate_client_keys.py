import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def main():
    kid = "client-k1"

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")

    pub = key.public_key().public_numbers()
    n = b64url(pub.n.to_bytes((pub.n.bit_length() + 7)//8, "big"))
    e = b64url(pub.e.to_bytes((pub.e.bit_length() + 7)//8, "big"))

    jwk = {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": n, "e": e}

    Path("client_private.pem").write_text(private_pem)
    Path("client_public.jwk.json").write_text(json.dumps(jwk))

    print("Wrote:")
    print(" - client_private.pem (KEEP SECRET; paste into Postman env var pkjwtPrivatePem)")
    print(" - client_public.jwk.json (REGISTER with /admin/set-client-jwk)")
    print("kid:", kid)

if __name__ == "__main__":
    main()
