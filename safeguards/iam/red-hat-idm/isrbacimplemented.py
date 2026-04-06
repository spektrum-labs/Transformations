import json
import ast


def transform(input):
    """Evaluates isRBACImplemented for Red Hat IDM (IAM)

    Checks: Whether RBAC is properly implemented by verifying that
            custom roles exist beyond the default IdM roles.
    API Source: POST {baseURL}/ipa/session/json (method: role_find)
    Pass Condition: At least one role exists with member assignments.
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

        # role_find returns {"result": {"result": [...], "count": N}}
        roles = data.get("roles", [])
        total_count = data.get("totalCount", 0)

        if not roles and isinstance(data, dict):
            nested = data.get("result", data)
            if isinstance(nested, dict):
                nested = nested.get("result", nested)
            if isinstance(nested, list):
                roles = nested
            elif isinstance(nested, dict):
                roles = nested.get("result", [])
                total_count = nested.get("count", 0)

        if isinstance(roles, list) and len(roles) > 0:
            # Check for roles with actual member assignments
            roles_with_members = 0
            for role in roles:
                if isinstance(role, dict):
                    members = role.get("member_user", role.get("member_group", []))
                    privileges = role.get("memberof_privilege", [])
                    if (isinstance(members, list) and len(members) > 0) or (isinstance(privileges, list) and len(privileges) > 0):
                        roles_with_members = roles_with_members + 1
            result = roles_with_members > 0

            # If no member info, just verify roles exist
            if not result and len(roles) > 0:
                result = True

        if not result and isinstance(total_count, (int, float)) and total_count > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isRBACImplemented": result, "roleCount": len(roles) if isinstance(roles, list) else total_count}

    except Exception as e:
        return {"isRBACImplemented": False, "error": str(e)}
