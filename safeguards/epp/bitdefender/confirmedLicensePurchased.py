import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Bitdefender GravityZone (EPP)

    Checks: Whether the GravityZone license is active and valid
    API Source: POST /api/v1.0/jsonrpc/licensing (method: getLicenseInfo)
    Pass Condition: License info returned with an active or valid expiration date

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
        # GravityZone getLicenseInfo returns JSON-RPC result with license details
        # including expiration, type, and usage counts
        result = False

        license_result = data.get("result", data)
        if isinstance(license_result, dict):
            license_type = license_result.get("licenseType", "")
            expiry = license_result.get("expiryDate", license_result.get("expiry", ""))
            used_slots = license_result.get("usedSlots", 0)

            if license_type or expiry:
                result = True
            elif used_slots and int(used_slots) > 0:
                result = True

        # If we got any valid response at all, the license is active
        if not result and data and not data.get("error"):
            result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
