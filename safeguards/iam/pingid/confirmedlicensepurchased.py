import json
import ast


def transform(input):
    """Evaluates confirmedLicensePurchased for PingID / PingOne (IAM)

    Validates that the PingOne environment has an active license by
    checking the licenses endpoint for an ACTIVE status.

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

        # PingOne /licenses returns embedded licenses array
        embedded = data.get("_embedded", data)
        licenses = embedded.get("licenses", [])
        if isinstance(licenses, list) and len(licenses) > 0:
            license_obj = licenses[0]
            status = license_obj.get("status", "")
            if isinstance(status, str) and status.upper() == "ACTIVE":
                result = True
        elif data.get("licensePurchased", False):
            result = True
        elif data.get("status", "").upper() == "ACTIVE":
            result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
