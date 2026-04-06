import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Nozomi Networks

    Checks: Whether the Nozomi Networks Guardian instance is healthy and licensed
    API Source: {baseURL}/api/open/query/do?query=health
    Pass Condition: Health endpoint responds with active system status

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
        health_status = data.get("status", data.get("health", ""))
        version = data.get("version", "")
        license_info = data.get("license", {})

        if isinstance(health_status, str):
            health_status = health_status.lower()

        valid_statuses = {"ok", "healthy", "active", "running"}
        result = health_status in valid_statuses or bool(version)
        plan = "guardian"
        status = "active" if result else "inactive"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "plan": plan,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
