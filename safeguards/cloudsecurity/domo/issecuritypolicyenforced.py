import json
import ast


def transform(input):
    """
    Evaluates isSecurityPolicyEnforced for Domo

    Checks: Whether Domo groups and access policies are configured
    API Source: {baseURL}/v1/groups
    Pass Condition: At least one group is configured for access control

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityPolicyEnforced": boolean, "totalGroups": int}
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
        groups = data.get("data", data.get("groups", data.get("results", data.get("items", []))))

        if isinstance(groups, list):
            total = len(groups)
        elif isinstance(groups, dict):
            total = groups.get("totalCount", groups.get("total", 0))
        else:
            total = 0

        result = total > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityPolicyEnforced": result,
            "totalGroups": total
        }

    except Exception as e:
        return {"isSecurityPolicyEnforced": False, "error": str(e)}
