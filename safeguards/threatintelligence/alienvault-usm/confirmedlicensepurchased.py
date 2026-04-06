import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for AlienVault USM Anywhere.

    Checks: Active USM Anywhere subscription via license endpoint
    API Source: GET https://{subdomain}.alienvault.cloud/api/2.0/license
    Pass Condition: Response contains valid license data without errors

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
        has_error = data.get("errors") is not None or data.get("error") is not None
        license_status = data.get("status", data.get("licenseStatus", ""))
        if isinstance(license_status, str):
            license_status = license_status.lower()

        active_statuses = {"active", "valid", "trial", "enterprise"}
        result = license_status in active_statuses or (isinstance(data, dict) and not has_error and len(data) > 0)
        status = "active" if result else "inactive"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
