import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for NetBox

    Checks: Whether the NetBox instance is running
    Pass Condition: netbox-version is present in response

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
        status = data.get("status", "")
        plan = data.get("plan", data.get("edition", "unknown"))

        if isinstance(status, str):
            status = status.lower()

        valid_statuses = {"active", "trial", "running", "healthy", "ok"}
        result = bool(status and status in valid_statuses)

        if not result:
            license_val = data.get("licensePurchased", data.get("netbox-version",
                data.get("active", data.get("id", ""))))
            result = bool(license_val)
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "plan": plan,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
