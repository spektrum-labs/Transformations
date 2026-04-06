import json
import ast


def transform(input):
    """Evaluates isAntiPhishingEnabled for Exchange Online (Email Security)"""
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

        alerts = data.get("value", [])
        if isinstance(alerts, list):
            result = True
            for alert in alerts:
                if isinstance(alert, dict):
                    category = alert.get("category", "")
                    if isinstance(category, str) and category.lower() in ("phishing", "malware"):
                        result = True
                        break
        # ── END EVALUATION LOGIC ──

        return {"isAntiPhishingEnabled": result}
    except Exception as e:
        return {"isAntiPhishingEnabled": False, "error": str(e)}
