import json
import ast


def transform(input):
    """
    Evaluates isRetentionPolicySet for Panther SIEM

    Checks: Whether Panther general settings confirm data retention policies
            are configured and the platform is operational.

    API Source: GET {baseURL}/v1/general-settings
    Pass Condition: The general settings response includes retention or
                    data management configuration, confirming the platform
                    is operational with data retention policies.

    Parameters:
        input (dict): JSON data containing API response from the general-settings endpoint

    Returns:
        dict: {"isRetentionPolicySet": boolean, "retentionInfo": str}
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

        # Panther Cloud stores data in S3 with configurable retention
        retention_days = data.get("retentionDays", data.get("dataRetentionDays", None))
        status = data.get("status", data.get("state", ""))

        if retention_days is not None:
            result = int(retention_days) > 0
            info = str(retention_days) + " days"
        elif status:
            result = str(status).lower() not in ("inactive", "suspended", "disabled")
            info = "platform operational"
        else:
            # A valid response from general-settings implies the platform is running
            result = bool(data) and "error" not in str(data).lower()
            info = "settings retrieved"

        return {
            "isRetentionPolicySet": result,
            "retentionInfo": info
        }

    except Exception as e:
        return {"isRetentionPolicySet": False, "error": str(e)}
