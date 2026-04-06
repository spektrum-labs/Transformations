import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Securonix SIEM

    Checks: Whether the Securonix instance is licensed and accessible by
            checking the token validation endpoint for a successful response.

    API Source: GET {baseURL}/ws/token/validate
    Pass Condition: The token validation returns a valid/true response,
                    confirming the instance is active and the API token is authorized.

    Parameters:
        input (dict): JSON data containing API response from the token validate endpoint

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "tokenStatus": str}
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

        # Standard response unwrapping chain
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # Securonix token validate returns validity status
        valid = data.get("valid", data.get("Valid", data.get("result", None)))
        status = data.get("status", "")

        if valid is not None:
            if isinstance(valid, bool):
                result = valid
            else:
                result = str(valid).lower() in ("true", "valid", "1")
        elif status:
            result = str(status).lower() in ("valid", "active", "ok")
        else:
            result = bool(data) and "error" not in str(data).lower() and "invalid" not in str(data).lower()

        return {
            "confirmedLicensePurchased": result,
            "tokenStatus": "valid" if result else "invalid"
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
