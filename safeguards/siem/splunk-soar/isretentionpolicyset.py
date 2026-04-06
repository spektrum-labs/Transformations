import json
import ast


def transform(input):
    """
    Evaluates isRetentionPolicySet for Splunk SOAR

    Checks: Whether the Splunk SOAR platform is operational and data management
            settings are in place by checking system info.

    API Source: GET {baseURL}/rest/system_info
    Pass Condition: The system info endpoint returns valid platform data
                    confirming the SOAR instance is operational with data management.

    Parameters:
        input (dict): JSON data containing API response from the system_info endpoint

    Returns:
        dict: {"isRetentionPolicySet": boolean, "platformStatus": str}
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

        # Splunk SOAR system_info returns platform operational data
        version = data.get("version", data.get("phantom_version", ""))
        status = data.get("status", "")

        if version:
            result = True
            platform_status = "operational"
        elif status:
            result = str(status).lower() not in ("error", "failed", "unavailable")
            platform_status = str(status)
        else:
            result = bool(data) and "error" not in str(data).lower()
            platform_status = "operational" if result else "unknown"

        return {
            "isRetentionPolicySet": result,
            "platformStatus": platform_status
        }

    except Exception as e:
        return {"isRetentionPolicySet": False, "error": str(e)}
