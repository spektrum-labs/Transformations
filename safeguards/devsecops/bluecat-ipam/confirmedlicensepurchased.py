import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for BlueCat IPAM (IP Address Management)

    Checks: Whether the BlueCat Address Manager session is valid and accessible
    API Source: GET {baseURL}/api/v2/sessions
    Pass Condition: API returns a valid session confirming active license

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean}
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

        # A valid session response confirms active Address Manager license
        if isinstance(data, dict):
            session_id = data.get("id", data.get("sessionId", ""))
            user = data.get("user", data.get("username", ""))
            token = data.get("token", data.get("apiToken", ""))
            if session_id or user or token:
                result = True
        elif isinstance(data, list) and len(data) > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
