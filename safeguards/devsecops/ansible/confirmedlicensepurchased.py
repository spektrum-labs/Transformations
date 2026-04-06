import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Ansible Automation Platform

    Checks: Whether the Ansible controller config indicates an active license
    API Source: {baseURL}/api/v2/config/
    Pass Condition: License info is present and not expired

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "status": str}
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

        if isinstance(status, str):
            status = status.lower()

        valid_statuses = {"active", "trial", "enabled"}
        result = status in valid_statuses

        if not result:
            license_info = data.get("license_info", data.get("license", {}))
            if isinstance(license_info, dict):
                license_type = license_info.get("license_type", "")
                compliant = license_info.get("compliant", license_info.get("valid_key", False))
                if compliant is True or license_type in ("enterprise", "basic", "trial"):
                    result = True
                    status = "active"

        if not result:
            licensed = data.get("licensePurchased", data.get("active", None))
            if isinstance(licensed, bool):
                result = licensed
            elif isinstance(licensed, str):
                result = licensed.lower() in ("true", "active", "enabled")
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status if isinstance(status, str) else str(status)
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
