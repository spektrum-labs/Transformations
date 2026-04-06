import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Akeyless

    Checks: Whether access roles and policies are configured for secret access control
    API Source: {baseURL}/list-roles
    Pass Condition: At least one access role is configured with active rules

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPipelineSecured": boolean, "activeRoles": int, "totalRoles": int}
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
        roles = data.get("roles", data.get("data", data.get("results", data.get("items", []))))

        if not isinstance(roles, list):
            return {
                "isPipelineSecured": False,
                "activeRoles": 0,
                "totalRoles": 0,
                "error": "Unexpected response format"
            }

        total = len(roles)
        active = []
        for role in roles:
            rules = role.get("rules", role.get("access_rules", []))
            if isinstance(rules, list) and len(rules) > 0:
                active.append(role)
            elif isinstance(rules, dict) and len(rules.keys()) > 0:
                active.append(role)

        result = len(active) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isPipelineSecured": result,
            "activeRoles": len(active),
            "totalRoles": total
        }

    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
