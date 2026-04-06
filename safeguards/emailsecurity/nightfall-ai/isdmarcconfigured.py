import json
import ast


def transform(input):
    """Evaluates isDMARCConfigured for Nightfall AI (Email Security)"""
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
        if isinstance(rules, list):
            for rule in rules:
                if isinstance(rule, dict):
                    name = rule.get("name", rule.get("displayName", "")).lower()
                    if "dmarc" in name or "email" in name or "sender" in name:
                        enabled = rule.get("enabled", rule.get("isEnabled", True))
                        if bool(enabled):
                            result = True
                            break
        # ── END EVALUATION LOGIC ──

        return {"isDMARCConfigured": result}
    except Exception as e:
        return {"isDMARCConfigured": False, "error": str(e)}
