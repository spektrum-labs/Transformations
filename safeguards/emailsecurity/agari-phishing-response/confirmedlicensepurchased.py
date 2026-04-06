import json
import ast
from datetime import datetime, timezone


def transform(input):
    """Evaluates confirmedLicensePurchased for Agari Phishing Response (Email Security)"""
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

        license_data = data.get("license", data)
        status = license_data.get("status", license_data.get("active", ""))

        if isinstance(status, bool):
            result = status
        elif isinstance(status, str):
            result = status.lower() in ("active", "valid", "enabled", "true")

        valid_until = license_data.get("valid_until", license_data.get("validUntil", ""))
        if valid_until and result:
            try:
                expiry = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                if expiry < datetime.now(timezone.utc):
                    result = False
            except (ValueError, AttributeError):
                pass
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
