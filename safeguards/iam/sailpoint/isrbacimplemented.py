import json
import ast


def transform(input):
    """Evaluates isRBACImplemented for SailPoint IdentityNow (IAM)

    Checks: Whether RBAC is properly implemented by verifying that
            defined roles exist with proper access profiles assigned.
    API Source: GET {baseURL}/v3/roles?limit=250
    Pass Condition: At least one role exists with access profiles or
                    entitlements assigned.
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
        if isinstance(roles, dict):
            roles = roles.get("items", roles.get("data", []))

        if isinstance(roles, list) and len(roles) > 0:
            roles_with_profiles = 0
            for role in roles:
                if isinstance(role, dict):
                    access_profiles = role.get("accessProfiles", role.get("entitlements", []))
                    enabled = role.get("enabled", role.get("active", True))
                    if isinstance(access_profiles, list) and len(access_profiles) > 0:
                        roles_with_profiles = roles_with_profiles + 1
                    elif enabled:
                        roles_with_profiles = roles_with_profiles + 1

            result = roles_with_profiles > 0
        # ── END EVALUATION LOGIC ──

        return {"isRBACImplemented": result, "roleCount": len(roles) if isinstance(roles, list) else 0}

    except Exception as e:
        return {"isRBACImplemented": False, "error": str(e)}
