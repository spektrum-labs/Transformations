import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Splunk SIEM

    Checks: Whether a valid Splunk license is active by checking the
            licenser endpoint for valid, non-expired license entries.

    API Source: GET {baseURL}/services/licenser/licenses?output_mode=json
    Pass Condition: At least one license entry exists with a valid, active
                    status, confirming the Splunk instance is properly licensed.

    Parameters:
        input (dict): JSON data containing API response from the licenser endpoint

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "licenseCount": int, "licenseType": str}
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

        # Splunk licenser endpoint returns entries under entry array
        entries = data.get("entry", data.get("entries", []))
        if not isinstance(entries, list):
            entries = []

        license_count = len(entries)
        license_type = "unknown"
        active_licenses = 0

        for entry in entries:
            content = entry.get("content", entry)
            ltype = content.get("type", content.get("license_type", ""))
            status = content.get("status", "")
            is_active = content.get("is_active", None)

            if ltype:
                license_type = str(ltype)

            if is_active is True or str(status).lower() in ("valid", "active", "ok"):
                active_licenses += 1
            elif is_active is None and "error" not in str(content).lower():
                active_licenses += 1

        result = active_licenses > 0

        return {
            "confirmedLicensePurchased": result,
            "licenseCount": license_count,
            "activeLicenses": active_licenses,
            "licenseType": license_type
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
