import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Panther SIEM

    Checks: Whether a valid Panther instance is active and licensed by
            checking the general settings endpoint for a successful response.

    API Source: GET {baseURL}/v1/general-settings
    Pass Condition: The API returns a valid settings object, confirming the
                    Panther instance is active with a valid subscription.

    Parameters:
        input (dict): JSON data containing API response from the general-settings endpoint

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "instanceStatus": str}
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

        # Panther general-settings returns org configuration
        status = data.get("status", data.get("state", ""))
        display_name = data.get("displayName", data.get("companyDisplayName", ""))

        # A successful response with settings data indicates an active license
        if status:
            result = str(status).lower() not in ("inactive", "suspended", "disabled", "expired")
        else:
            result = bool(data) and "error" not in str(data).lower()

        return {
            "confirmedLicensePurchased": result,
            "instanceStatus": str(status) if status else "active",
            "displayName": str(display_name) if display_name else "unknown"
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
