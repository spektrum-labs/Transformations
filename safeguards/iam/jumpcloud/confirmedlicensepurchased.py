import json
import ast


def transform(input):
    """Evaluates confirmedLicensePurchased for JumpCloud (IAM)

    Validates that a JumpCloud organization exists with an active entitlement
    by checking the organizations endpoint for valid subscription data.

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

        # JumpCloud /api/organizations returns org details with entitlement info
        results = data.get("results", [])
        if isinstance(results, list) and len(results) > 0:
            org = results[0] if isinstance(results[0], dict) else {}
            entitlement = org.get("entitlement", {})
            is_active = entitlement.get("isActive", entitlement.get("isManaged", False))
            if is_active is True or str(is_active).lower() == "true":
                result = True
            elif org.get("_id", org.get("id", "")):
                # Org exists with an ID, subscription is active
                result = True
        elif data.get("licensePurchased", False):
            result = True
        elif data.get("status", "") != "":
            result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
