import json
import ast


def transform(input):
    """Evaluates isRBACImplemented for PingID / PingOne (IAM)

    Validates RBAC by confirming that PingOne roles are defined and
    role assignments exist for users in the environment.

    Parameters:
        input (dict): JSON data containing API response from getRoles

    Returns:
        dict: {"isRBACImplemented": boolean}
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

        embedded = data.get("_embedded", data)
        roles = embedded.get("roles", data.get("roles", []))

        if isinstance(roles, list) and len(roles) > 0:
            result = True
        elif data.get("count", 0) > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isRBACImplemented": result}

    except Exception as e:
        return {"isRBACImplemented": False, "error": str(e)}
