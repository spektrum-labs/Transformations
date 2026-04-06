import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for JFrog Platform

    Checks: Whether the JFrog Platform has an active license
    API Source: {baseURL}/artifactory/api/system/licenses
    Pass Condition: License type exists and is valid (not expired)

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "plan": str, "status": str}
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

        # -- EVALUATION LOGIC --
        license_type = data.get("type", data.get("licenseType", ""))
        valid_through = data.get("validThrough", data.get("expirationDate", ""))
        licensed_to = data.get("licensedTo", "")

        result = bool(license_type) and bool(licensed_to)
        plan = license_type if license_type else "unknown"
        status = "active" if result else "inactive"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "plan": plan,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
