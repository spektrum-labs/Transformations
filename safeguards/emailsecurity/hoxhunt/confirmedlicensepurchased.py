import json
import ast
from datetime import datetime, timezone


def transform(input):
    """Evaluates confirmedLicensePurchased for Hoxhunt (Email Security)"""
    try:
        def _parse_input(raw):
            if isinstance(raw, str):
                try:
                    parsed = ast.literal_eval(raw)
                    if isinstance(parsed, dict): return parsed
                except: pass
                try:
                    raw = raw.replace("'", '"')
                    return json.loads(raw)
                except: raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(raw, bytes): return json.loads(raw.decode("utf-8"))
            if isinstance(raw, dict): return raw
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # ── EVALUATION LOGIC ──
        result = False

        gql_data = data.get("data", data)
        org = gql_data.get("organization", gql_data)
        licensing = org.get("licensingStatus", org.get("license", {}))

        if isinstance(licensing, dict):
            active = licensing.get("active", licensing.get("status", False))
            if isinstance(active, bool):
                result = active
            elif isinstance(active, str):
                result = active.lower() in ("active", "valid", "enabled", "true")

            expires_at = licensing.get("expiresAt", licensing.get("validUntil", ""))
            if expires_at and result:
                try:
                    expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=timezone.utc)
                    if expiry < datetime.now(timezone.utc):
                        result = False
                except (ValueError, AttributeError):
                    pass

        if not result and org.get("id"):
            result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
