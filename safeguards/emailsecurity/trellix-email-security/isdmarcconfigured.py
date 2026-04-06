import json
import ast


def transform(input):
    """Evaluates isDMARCConfigured for Trellix Email Security (Email Security)"""
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

        config = data.get("config", data.get("settings", data))
        dmarc = config.get("dmarc", config.get("dmarcPolicy", config.get("dmarc_enforcement", None)))
        if dmarc is True:
            result = True
        elif isinstance(dmarc, str) and dmarc.lower() in ("reject", "quarantine", "enabled", "enforced"):
            result = True
        elif isinstance(dmarc, dict):
            policy = dmarc.get("policy", dmarc.get("status", ""))
            if isinstance(policy, str) and policy.lower() in ("reject", "quarantine", "enabled", "active"):
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isDMARCConfigured": result}
    except Exception as e:
        return {"isDMARCConfigured": False, "error": str(e)}
