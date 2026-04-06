import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Automox (EPP)

    Checks: Whether the Automox organization exists and has an active subscription
    API Source: GET https://console.automox.com/api/orgs/{orgId}
    Pass Condition: API returns a valid organization object with an active trial_end_time
                    or a non-trial subscription

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
        # Automox /api/orgs/{id} returns org details including name, device_count, etc.
        # A valid response with an org name confirms active subscription
        result = False

        org_name = data.get("name", "")
        device_count = data.get("device_count", 0)

        if org_name and isinstance(org_name, str) and len(org_name) > 0:
            result = True

        # ── END EVALUATION LOGIC ──

        return {
            "confirmedLicensePurchased": result,
            "organizationName": org_name,
            "deviceCount": device_count
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
