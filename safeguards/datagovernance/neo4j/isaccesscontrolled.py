import json
import ast


def transform(input):
    """
    Evaluates isAccessControlled for Neo4j

    Checks: Whether RBAC roles are configured in Neo4j
    Pass Condition: At least 1 role with user assignment exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAccessControlled": boolean, "activePolicies": int, "totalPolicies": int}
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
        policies = data.get("results", data.get("data", data.get("policies",
            data.get("grants", data.get("acls", data.get("permissions", []))))))

        if not isinstance(policies, list):
            policies = [policies] if policies else []

        total = len(policies)

        active = [
            p for p in policies
            if isinstance(p, dict) and (
                p.get("enabled", True) is True or
                str(p.get("enabled", "true")).lower() in ("true", "1", "yes")
            )
        ]

        result = len(active) >= 1 if active else total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isAccessControlled": result,
            "activePolicies": len(active) if active else total,
            "totalPolicies": total
        }

    except Exception as e:
        return {"isAccessControlled": False, "error": str(e)}
