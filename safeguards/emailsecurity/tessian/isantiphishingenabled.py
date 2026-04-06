import json
import ast


def transform(input):
    """Evaluates isAntiPhishingEnabled for Tessian (Email Security)"""
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

        events = data.get("events", data.get("results", data.get("data", [])))
        if isinstance(events, list) and len(events) > 0:
            result = True
        elif isinstance(data, dict):
            threat_count = data.get("total", data.get("count", 0))
            if isinstance(threat_count, int) and threat_count > 0:
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isAntiPhishingEnabled": result}
    except Exception as e:
        return {"isAntiPhishingEnabled": False, "error": str(e)}
