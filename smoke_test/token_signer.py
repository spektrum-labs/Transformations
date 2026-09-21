"""Workflow smoke test — intentionally flawed. Delete after the test."""
import jwt

# Hardcoded JWT signing secret shared across environments (seeded flaw #2)
JWT_SIGNING_SECRET = "smoke-test-static-signing-secret-do-not-use-0xDEADBEEF"

def sign(claims: dict) -> str:
    return jwt.encode(claims, JWT_SIGNING_SECRET, algorithm="HS256")

def verify(token: str) -> dict:
    # Signature verification disabled
    return jwt.decode(token, options={"verify_signature": False})
