import json
import ast


def transform(input):
    """Evaluates confirmedLicensePurchased for Nightfall AI (Email Security)"""
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

        rules = data.get("detectionRules", data.get("data", data.get("rules", [])))
        if isinstance(rules, list) and len(rules) > 0:
            result = True

        status = data.get("status", data.get("active", None))
        if status is not None:
            if isinstance(status, bool):
                result = status
            elif isinstance(status, str):
                result = status.lower() in ("active", "enabled", "valid", "true")
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
