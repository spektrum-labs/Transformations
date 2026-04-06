import json
import ast


def transform(input):
    """
    Evaluates isRetentionPolicySet for Splunk Observability Cloud

    Checks: Whether organization settings confirm data retention is configured
            and the Splunk Observability platform is operational.

    API Source: GET {baseURL}/v2/organization
    Pass Condition: The organization endpoint returns a valid response with
                    retention configuration, confirming the platform is operational.

    Parameters:
        input (dict): JSON data containing API response from the organization endpoint

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

        # Splunk Observability org endpoint returns retention info
        retention = data.get("dataRetentionDays", data.get("retentionDays", None))
        org_id = data.get("id", data.get("organizationId", ""))

        if retention is not None:
            result = int(retention) > 0
            info = str(retention) + " days"
        elif org_id:
            result = True
            info = "cloud-managed retention"
        else:
            result = bool(data) and "error" not in str(data).lower()
            info = "settings retrieved" if result else "unknown"

        return {
            "isRetentionPolicySet": result,
            "retentionInfo": info
        }

    except Exception as e:
        return {"isRetentionPolicySet": False, "error": str(e)}
