import json
import ast


def transform(input):
    """
    Evaluates isComplianceMonitored for Adaptive Shield

    Checks: Whether security checks (controls) are configured and actively monitored
    API Source: {baseURL}/api/v1/security-checks
    Pass Condition: At least 1 security check exists with an active status

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isComplianceMonitored": boolean, "activeControls": int, "totalControls": int}
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
        controls = data.get("results", data.get("data", data.get("items", data.get("security_checks", []))))

        if not isinstance(controls, list):
            return {
                "isComplianceMonitored": False,
                "activeControls": 0,
                "totalControls": 0,
                "error": "Unexpected controls response format"
            }

        total = len(controls)
        active = [
            c for c in controls
            if str(c.get("status", "")).lower() in ("active", "enabled", "passing", "monitored")
        ]
        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isComplianceMonitored": result,
            "activeControls": len(active),
            "totalControls": total
        }

    except Exception as e:
        return {"isComplianceMonitored": False, "error": str(e)}
