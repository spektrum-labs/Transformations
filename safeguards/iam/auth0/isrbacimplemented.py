import json
import ast


def transform(input):
    """
    Evaluates isRBACImplemented for Auth0 (IAM)

    Checks: Whether roles are defined in Auth0 for role-based access control
    API Source: GET {baseURL}/api/v2/roles
    Pass Condition: At least two roles exist indicating RBAC structure is in place
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

        # Auth0 /api/v2/roles returns a list of role objects
        roles = data if isinstance(data, list) else data.get("roles", data.get("data", []))

        if isinstance(roles, list) and len(roles) >= 2:
            result = True
        elif isinstance(data.get("total", data.get("length", 0)), (int, float)):
            total = data.get("total", data.get("length", 0))
            result = total >= 2
        # ── END EVALUATION LOGIC ──

        return {"isRBACImplemented": result}

    except Exception as e:
        return {"isRBACImplemented": False, "error": str(e)}
