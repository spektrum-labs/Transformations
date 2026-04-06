import json
import ast


def transform(input):
    """Evaluates confirmedLicensePurchased for Passwordstate (IAM)

    Validates that the Passwordstate instance is active by confirming the
    API returns user records from the security administration endpoint.

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

        # Passwordstate returns user records; existence confirms active license
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
        elif data.get("UserID", data.get("UserName", "")) != "":
            result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
