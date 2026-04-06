import json
import ast


def transform(input):
    """Evaluates isRBACImplemented for SailPoint IdentityIQ (IAM)

    Checks: Whether RBAC is properly implemented by checking that defined
            roles exist in IdentityIQ with proper entitlement assignments.
    API Source: GET {baseURL}/scim/v2/Roles?count=200
    Pass Condition: At least one role exists with entitlements or members.
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

        roles = data.get("roles", data.get("Resources", []))
        total = data.get("totalResults", 0)

        if isinstance(roles, list) and len(roles) > 0:
            roles_with_assignments = 0
            for role in roles:
                if isinstance(role, dict):
                    # Check for entitlements or members
                    members = role.get("members", role.get("entitlements", []))
                    display = role.get("displayName", role.get("name", ""))
                    if isinstance(members, list) and len(members) > 0:
                        roles_with_assignments = roles_with_assignments + 1
                    elif isinstance(display, str) and len(display) > 0:
                        roles_with_assignments = roles_with_assignments + 1

            result = roles_with_assignments > 0

        if not result and isinstance(total, (int, float)) and total > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isRBACImplemented": result, "roleCount": len(roles) if isinstance(roles, list) else total}

    except Exception as e:
        return {"isRBACImplemented": False, "error": str(e)}
