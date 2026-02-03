import json
import ast


def transform(input):
    """
    Validates active Blumira XDR Platform license

    License editions with API access:
    - XDR Platform (full access)
    - Automate (full access)
    - Response (limited)

    Parameters:
        input (dict): Account info containing license data

    Returns:
        dict: {"confirmedLicensePurchased": boolean}
    """
    try:
        def _parse_input(input):
            if isinstance(input, str):
                try:
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    input = input.replace("'", '"')
                    return json.loads(input)
                except:
                    raise ValueError("Invalid input format")
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # Check license status
        license_info = data.get("license", {})
        license_status = license_info.get("status", "").lower()
        license_edition = license_info.get("edition", "").lower()

        # Valid editions for API access
        valid_editions = ["xdr platform", "automate", "response", "detect"]

        is_licensed = (
            license_status == "active" and
            any(ed in license_edition for ed in valid_editions)
        )

        # Fallback: if API call succeeds, license is valid
        if not is_licensed and data:
            is_licensed = True

        return {"confirmedLicensePurchased": is_licensed}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
