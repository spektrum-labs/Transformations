import json
import ast


def transform(input):
    """
    Evaluates isRBACImplemented for Active Directory On-Prem (IAM)

    Checks: Whether security groups are used to implement role-based access control
    API Source: GET {baseURL}/api/groups
    Pass Condition: Multiple security groups exist with member assignments indicating RBAC structure
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

        groups = data.get("groups", data.get("data", data.get("value", [])))
        if isinstance(groups, list) and len(groups) >= 2:
            # Check that groups have members assigned (indicating active RBAC)
            groups_with_members = [
                g for g in groups
                if g.get("memberCount", g.get("members", 0))
                or (isinstance(g.get("members", []), list) and len(g.get("members", [])) > 0)
            ]
            result = len(groups_with_members) >= 2
        elif isinstance(data.get("count", data.get("totalCount", 0)), (int, float)):
            total = data.get("count", data.get("totalCount", 0))
            result = total >= 2
        # ── END EVALUATION LOGIC ──

        return {"isRBACImplemented": result}

    except Exception as e:
        return {"isRBACImplemented": False, "error": str(e)}
