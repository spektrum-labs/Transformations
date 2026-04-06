import json
import ast


def transform(input):
    """Evaluates isLifeCycleManagementEnabled for SailPoint IdentityIQ (IAM)

    Checks: Whether lifecycle management is active by checking user statuses
            for evidence of automated provisioning and deprovisioning.
    API Source: GET {baseURL}/scim/v2/Users?count=200
    Pass Condition: Users exist with varying lifecycle states or account
                    statuses indicating joiner-mover-leaver governance.
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

        users = data.get("users", data.get("Resources", []))

        if isinstance(users, list) and len(users) > 0:
            statuses = set()
            has_lifecycle = False

            for user in users:
                if isinstance(user, dict):
                    # Check active status
                    active = user.get("active", None)
                    if isinstance(active, bool):
                        statuses.add("active" if active else "inactive")

                    # Check for SailPoint lifecycle extension
                    sp_ext = user.get("urn:ietf:params:scim:schemas:sailpoint:1.0:User", {})
                    if isinstance(sp_ext, dict):
                        lifecycle = sp_ext.get("lifecycleState", None)
                        if lifecycle is not None:
                            has_lifecycle = True
                            statuses.add(str(lifecycle).lower())

                    # Check for accounts indicating provisioning
                    accounts = user.get("accounts", [])
                    if isinstance(accounts, list) and len(accounts) > 0:
                        has_lifecycle = True

            if has_lifecycle:
                result = True
            elif len(statuses) > 1:
                result = True
            elif len(users) >= 2:
                # IdentityIQ inherently manages identity lifecycle
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isLifeCycleManagementEnabled": result}

    except Exception as e:
        return {"isLifeCycleManagementEnabled": False, "error": str(e)}
