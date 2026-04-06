import json
import ast


def transform(input):
    """
    Evaluates isSecurityPolicyEnforced for Snipe-IT

    Checks: Whether status labels are configured to enforce asset lifecycle policies
    API Source: {baseURL}/statuslabels
    Pass Condition: At least one status label exists and is in a deployable state

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityPolicyEnforced": boolean, "activePolicies": int, "totalPolicies": int}
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
        rows = data.get("rows", data.get("data", data.get("results", data.get("items", []))))

        if not isinstance(rows, list):
            return {
                "isSecurityPolicyEnforced": False,
                "activePolicies": 0,
                "totalPolicies": 0,
                "error": "Unexpected status labels response format"
            }

        total = len(rows)
        active = []
        for label in rows:
            labelType = label.get("type", "")
            if isinstance(labelType, str) and labelType.lower() in ("deployable", "pending", "undeployable", "archived"):
                active.append(label)

        result = len(active) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityPolicyEnforced": result,
            "activePolicies": len(active),
            "totalPolicies": total
        }

    except Exception as e:
        return {"isSecurityPolicyEnforced": False, "error": str(e)}
