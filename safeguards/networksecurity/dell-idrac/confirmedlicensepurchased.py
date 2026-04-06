import json
import ast


def transform(input):
    """Evaluates confirmedLicensePurchased for Dell iDRAC (Network Security)"""
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
                    raise ValueError("Invalid input")
            if isinstance(raw, bytes):
                return json.loads(raw.decode("utf-8"))
            if isinstance(raw, dict):
                return raw
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # -- EVALUATION LOGIC --
        result = False

        # iDRAC DellLicenseCollection returns Members array with license objects
        members = data.get("Members", data.get("members", []))
        if isinstance(members, list) and len(members) > 0:
            result = True
        else:
            # Fallback: check for license description or entitlement ID
            license_desc = data.get("LicenseDescription", data.get("EntitlementID", ""))
            if license_desc and isinstance(license_desc, str) and len(license_desc) > 0:
                result = True

        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
