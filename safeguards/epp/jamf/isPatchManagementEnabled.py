import json
import ast


def transform(input):
    """
    Evaluates isPatchManagementEnabled for Jamf Pro (EPP)

    Checks: Whether Jamf Pro patch management software title configurations exist
    API Source: GET /api/v2/patch-software-title-configurations
    Pass Condition: At least one patch software title configuration is present

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPatchManagementEnabled": boolean, ...metadata}
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

        # ── EVALUATION LOGIC ──
        result = False
        policies = data.get("results", data.get("policies", data.get("data", [])))
        if not isinstance(policies, list):
            policies = []

        total = data.get("totalCount", len(policies))
        enabled = 0
        for p in policies:
            if p.get("enabled", True):
                enabled += 1

        if total > 0 and enabled > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isPatchManagementEnabled": result,
            "enabledPolicies": enabled,
            "totalPolicies": total
        }

    except Exception as e:
        return {"isPatchManagementEnabled": False, "error": str(e)}
