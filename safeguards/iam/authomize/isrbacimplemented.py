import json
import ast


def transform(input):
    """
    Evaluates isRBACImplemented for Authomize (IAM)

    Checks: Whether RBAC is implemented with defined privilege sets
    API Source: GET {baseURL}/v2/privileges
    Pass Condition: At least two privilege/role definitions exist
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

        privileges = data.get("privileges", data.get("data", data.get("items", [])))

        if isinstance(privileges, list) and len(privileges) >= 2:
            result = True
        elif isinstance(data.get("totalCount", data.get("total", 0)), (int, float)):
            total = data.get("totalCount", data.get("total", 0))
            result = total >= 2
        # ── END EVALUATION LOGIC ──

        return {"isRBACImplemented": result}

    except Exception as e:
        return {"isRBACImplemented": False, "error": str(e)}
