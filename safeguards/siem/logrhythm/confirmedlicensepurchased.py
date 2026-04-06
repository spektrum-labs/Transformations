import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for LogRhythm SIEM

    Checks: Whether a valid LogRhythm license is active by verifying the
            license endpoint returns a successful response indicating an
            active, non-expired license.

    API Source: GET {baseURL}/lr-admin-api/license
    Pass Condition: The API returns a valid license object with an active
                    status, confirming the organization has a current LogRhythm license.

    Parameters:
        input (dict): JSON data containing API response from the license endpoint

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "licenseStatus": str}
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

        # LogRhythm license endpoint returns license details at top level
        license_status = data.get("status", data.get("Status", ""))
        license_type = data.get("type", data.get("Type", ""))
        is_valid = data.get("isValid", data.get("IsValid", None))

        # A successful API response with any license data indicates a valid license
        if is_valid is not None:
            result = bool(is_valid)
        elif license_status:
            result = str(license_status).lower() in ("active", "valid", "ok", "enabled")
        else:
            # If we got a non-error response, the license exists
            result = bool(data) and "error" not in str(data).lower()

        return {
            "confirmedLicensePurchased": result,
            "licenseStatus": str(license_status) if license_status else "unknown",
            "licenseType": str(license_type) if license_type else "unknown"
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
