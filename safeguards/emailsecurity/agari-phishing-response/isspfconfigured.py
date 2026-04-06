import json
import ast


def transform(input):
    """Evaluates isSPFConfigured for Agari Phishing Response (Email Security)"""
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

        policy = data.get("policy", data.get("status", data))
        if isinstance(policy, dict):
            spf = policy.get("spf", policy.get("spfConfigured", policy.get("spf_status", None)))
            if spf is not None:
                if isinstance(spf, bool):
                    result = spf
                elif isinstance(spf, str):
                    result = spf.lower() in ("pass", "enabled", "configured", "true", "active")
                elif isinstance(spf, dict):
                    result = bool(spf.get("enabled", spf.get("configured", False)))
        # ── END EVALUATION LOGIC ──

        return {"isSPFConfigured": result}
    except Exception as e:
        return {"isSPFConfigured": False, "error": str(e)}
