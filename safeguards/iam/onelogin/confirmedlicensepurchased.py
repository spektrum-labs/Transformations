import json
import ast


def transform(input):
    """Evaluates confirmedLicensePurchased for OneLogin (IAM)

    Validates that the OneLogin tenant is active by confirming the API
    returns user records, indicating an active subscription.

    Parameters:
        input (dict): JSON data containing API response from getLicenseStatus

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

        # OneLogin /api/2/users returns array of users; if any exist, tenant is active
        users = data.get("data", data.get("users", []))
        if isinstance(users, list) and len(users) > 0:
            result = True
        elif isinstance(data, list) and len(data) > 0:
            # API may return array directly
            result = True
        elif data.get("licensePurchased", False):
            result = True
        elif data.get("status", "") not in ("", None):
            result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
