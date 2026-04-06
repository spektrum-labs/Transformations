import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for PlexTrac (ASM)

    Checks: Whether PlexTrac authentication returns a valid JWT token
    API Source: {baseURL}/api/v1/authenticate
    Pass Condition: Response contains a valid token confirming active subscription

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "status": str}
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
        token = data.get("token", data.get("access_token", ""))
        tenant_id = data.get("tenant_id", data.get("tenantId", ""))
        status_code = data.get("status_code", data.get("statusCode", 200))

        valid = bool(token) and status_code in (200, 201)
        status = "active" if valid else "invalid"
        # ── END EVALUATION LOGIC ──

        return {
            "confirmedLicensePurchased": valid,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
