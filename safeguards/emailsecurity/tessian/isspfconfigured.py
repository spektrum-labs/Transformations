import json
import ast


def transform(input):
    """Evaluates isSPFConfigured for Tessian (Email Security)"""
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

        settings = data.get("settings", data)
        spf = settings.get("spf", settings.get("spfEnabled", settings.get("spf_enabled", None)))
        if spf is True:
            result = True
        elif isinstance(spf, str) and spf.lower() in ("true", "enabled", "active", "pass"):
            result = True
        elif isinstance(spf, dict):
            status = spf.get("status", spf.get("enabled", ""))
            if isinstance(status, str) and status.lower() in ("enabled", "active", "configured", "pass"):
                result = True
            elif status is True:
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isSPFConfigured": result}
    except Exception as e:
        return {"isSPFConfigured": False, "error": str(e)}
