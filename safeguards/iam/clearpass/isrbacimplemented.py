import json
import ast


def transform(input):
    """
    Evaluates isRBACImplemented for ClearPass (IAM)

    Checks: Whether roles are defined for access control in ClearPass
    API Source: GET {baseURL}/api/role
    Pass Condition: At least two roles exist indicating RBAC structure is configured
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

        # ClearPass /api/role returns roles in _embedded.items format
        items = data.get("_embedded", {}).get("items", data.get("items", data.get("data", [])))
        count = data.get("count", data.get("total", 0))

        if isinstance(items, list) and len(items) >= 2:
            result = True
        elif isinstance(count, (int, float)) and count >= 2:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isRBACImplemented": result}

    except Exception as e:
        return {"isRBACImplemented": False, "error": str(e)}
