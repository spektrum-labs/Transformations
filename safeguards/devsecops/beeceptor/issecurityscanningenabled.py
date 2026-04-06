import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for Beeceptor (API Mocking)

    Checks: Whether Beeceptor endpoints are configured and actively capturing requests
    API Source: GET https://app.beeceptor.com/api/v2/endpoints
    Pass Condition: At least one active endpoint exists with mocking rules configured

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean}
    """
    try:
        def _parse_input(raw):
            if isinstance(raw, str):
                try:
                    parsed = ast.literal_eval(raw)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    raw = raw.replace("'", '"')
                    return json.loads(raw)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(raw, bytes):
                return json.loads(raw.decode("utf-8"))
            if isinstance(raw, dict):
                return raw
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # ── EVALUATION LOGIC ──
        result = False

        # Check for active endpoints indicating scanning/mocking is enabled
        endpoints = data if isinstance(data, list) else data.get("endpoints", data.get("data", []))
        if isinstance(endpoints, list) and len(endpoints) > 0:
            for ep in endpoints:
                if isinstance(ep, dict) and (ep.get("name") or ep.get("subdomain")):
                    result = True
                    break
        # ── END EVALUATION LOGIC ──

        return {"isSecurityScanningEnabled": result}
    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
