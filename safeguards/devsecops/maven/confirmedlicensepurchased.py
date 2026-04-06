import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Maven Repository Manager

    Checks: Whether the Maven repository manager has an active license
    API Source: {baseURL}/service/rest/v1/system/license
    Pass Condition: License exists and reports valid status

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
        contact_company = data.get("contactCompany", "")
        contact_email = data.get("contactEmail", "")
        license_type = data.get("licenseType", data.get("type", ""))
        effective_date = data.get("effectiveDate", "")
        expiration_date = data.get("expirationDate", "")

        result = bool(contact_company) or bool(contact_email) or bool(license_type)
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
