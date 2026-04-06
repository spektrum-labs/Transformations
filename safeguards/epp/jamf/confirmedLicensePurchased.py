import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Jamf Pro (EPP)

    Checks: Whether the Jamf Pro instance is active and licensed
    API Source: GET /api/v1/jamf-pro-information
    Pass Condition: API returns valid instance information confirming active subscription

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
        # Jamf Pro /api/v1/jamf-pro-information returns instance details
        # including vppTokenEnabled, isVppTokenEnabled, etc.
        result = False

        version = data.get("version", data.get("jamfProVersion", ""))
        is_managed = data.get("managedComputers", data.get("totalManaged", 0))

        if version and isinstance(version, str) and len(version) > 0:
            result = True
        elif is_managed and int(is_managed) > 0:
            result = True
        elif data and not data.get("error") and not data.get("httpStatus"):
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "confirmedLicensePurchased": result,
            "jamfProVersion": version
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
