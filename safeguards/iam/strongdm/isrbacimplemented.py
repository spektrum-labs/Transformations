import json
import ast


def transform(input):
    """Evaluates isRBACImplemented for StrongDM (IAM)

    Checks: Whether RBAC is properly implemented by checking that defined
            roles exist with proper resource access grants in StrongDM.
    API Source: GET {baseURL}/v1/roles
    Pass Condition: At least one role exists with resource grants assigned.
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

        roles = data.get("roles", data)
        total = data.get("totalCount", data.get("meta", {}).get("total", 0))

        if isinstance(roles, dict):
            roles = roles.get("items", roles.get("data", []))

        if isinstance(roles, list) and len(roles) > 0:
            roles_with_grants = 0
            for role in roles:
                if isinstance(role, dict):
                    # Check for resource grants
                    grants = role.get("accessRules", role.get("grants", role.get("resources", [])))
                    name = role.get("name", role.get("displayName", ""))
                    managed = role.get("managed", role.get("composite", False))

                    if isinstance(grants, list) and len(grants) > 0:
                        roles_with_grants = roles_with_grants + 1
                    elif isinstance(name, str) and len(name) > 0:
                        roles_with_grants = roles_with_grants + 1

            result = roles_with_grants > 0

        if not result and isinstance(total, (int, float)) and total > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isRBACImplemented": result, "roleCount": len(roles) if isinstance(roles, list) else total}

    except Exception as e:
        return {"isRBACImplemented": False, "error": str(e)}
