import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for Cycode (Software Supply Chain Security)

    Checks: Whether secret detection scanning is enabled and operational
    API Source: GET https://api.cycode.com/api/v1/secrets/status
    Pass Condition: Secret scanning status indicates the feature is enabled and active

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

        # -- EVALUATION LOGIC --
        result = False

        # Check if secret detection scanning is enabled
        status = data.get("status", data.get("state", ""))
        enabled = data.get("enabled", data.get("active", False))
        if enabled:
            result = True
        elif str(status).lower() in ("enabled", "active", "running", "ok"):
            result = True
        elif data.get("data", {}).get("enabled") or data.get("data", {}).get("active"):
            result = True
        elif isinstance(data, dict) and len(data) > 0 and not data.get("error"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"isSecretManagementEnabled": result}
    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
