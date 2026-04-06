import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Elasticsearch

    Checks: Whether the Elasticsearch cluster has a valid active license
    API Source: /_license
    Pass Condition: License status is 'active' and type is not 'expired'

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "licenseType": str, "status": str}
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
        license_info = data.get("license", data)
        status = str(license_info.get("status", "")).lower()
        license_type = str(license_info.get("type", "unknown")).lower()

        valid_statuses = {"active", "valid"}
        result = status in valid_statuses
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "licenseType": license_type,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
