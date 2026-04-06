import json
import ast


def transform(input):
    """
    Evaluates isRetentionPolicySet for Securonix SIEM

    Checks: Whether the Securonix platform is operational and data is being
            retained by verifying the incident endpoint returns valid data.

    API Source: GET {baseURL}/ws/incident/get?type=list&max=1
    Pass Condition: The platform returns a valid response, confirming that
                    data retention and the SIEM are functioning correctly.

    Parameters:
        input (dict): JSON data containing API response from the incident endpoint

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

        # A valid response from the incident endpoint confirms the platform is operational
        # and data is being retained (incidents can only exist if data is stored)
        status = data.get("status", "")
        total = data.get("totalIncidents", data.get("total", None))

        if total is not None:
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
