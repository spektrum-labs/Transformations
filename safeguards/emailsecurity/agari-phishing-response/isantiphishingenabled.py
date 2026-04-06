import json
import ast


def transform(input):
    """Evaluates isAntiPhishingEnabled for Agari Phishing Response (Email Security)"""
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

        incidents = data.get("incidents", data.get("data", []))
        if isinstance(incidents, list) and len(incidents) >= 0:
            result = True

        policies = data.get("policies", data.get("policy", {}))
        if isinstance(policies, dict):
            phishing_enabled = policies.get("phishing_detection", policies.get("enabled", None))
            if phishing_enabled is not None:
                result = bool(phishing_enabled)
        # ── END EVALUATION LOGIC ──

        return {"isAntiPhishingEnabled": result}
    except Exception as e:
        return {"isAntiPhishingEnabled": False, "error": str(e)}
