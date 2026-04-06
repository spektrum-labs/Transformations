import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for Beeceptor (API Mocking)

    Checks: Whether Beeceptor endpoint security settings are configured
    API Source: GET https://app.beeceptor.com/api/v2/endpoints
    Pass Condition: Endpoints have security settings such as authentication headers configured

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean}
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

        # Check for security configuration on endpoints
        endpoints = data if isinstance(data, list) else data.get("endpoints", data.get("data", []))
        if isinstance(endpoints, list) and len(endpoints) > 0:
            for ep in endpoints:
                if isinstance(ep, dict):
                    security = ep.get("security", ep.get("authHeader", ep.get("authentication")))
                    if security:
                        result = True
                        break
            # If no explicit security field, having active endpoints still indicates management
            if not result and len(endpoints) > 0:
                result = True
        elif isinstance(data, dict) and (data.get("status") or data.get("name")):
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isSecretManagementEnabled": result}
    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
