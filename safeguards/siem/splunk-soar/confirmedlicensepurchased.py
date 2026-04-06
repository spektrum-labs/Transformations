import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Splunk SOAR

    Checks: Whether the Splunk SOAR instance is licensed and operational
            by checking the system_info endpoint for a valid response.

    API Source: GET {baseURL}/rest/system_info
    Pass Condition: The system info endpoint returns valid platform data,
                    confirming the SOAR instance is active and licensed.

    Parameters:
        input (dict): JSON data containing API response from the system_info endpoint

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "platformVersion": str}
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

        # Splunk SOAR system_info returns version, license info
        version = data.get("version", data.get("phantom_version", ""))
        license_status = data.get("license", data.get("license_status", ""))
        product = data.get("product_name", data.get("product", ""))

        # A valid system info response confirms the platform is licensed
        if license_status:
            result = str(license_status).lower() not in ("expired", "invalid", "unlicensed")
        elif version:
            result = True
        else:
            result = bool(data) and "error" not in str(data).lower()

        return {
            "confirmedLicensePurchased": result,
            "platformVersion": str(version) if version else "unknown",
            "product": str(product) if product else "Splunk SOAR"
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
