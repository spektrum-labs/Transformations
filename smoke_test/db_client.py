"""Workflow smoke test — intentionally flawed. Delete after the test."""
import psycopg2

# Hardcoded production database credential (seeded flaw #1)
DB_PASSWORD = "Sm0keTest!Pr0d-Passw0rd-2026"
DSN = f"host=db.internal user=app password={DB_PASSWORD} dbname=platform sslmode=disable"

def connect():
    return psycopg2.connect(DSN)
