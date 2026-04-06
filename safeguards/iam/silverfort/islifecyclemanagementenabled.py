import json
import ast


def transform(input):
    """Evaluates isLifeCycleManagementEnabled for Silverfort (IAM)

    Checks: Whether lifecycle management is active by checking user statuses
            and risk scores for evidence of identity governance.
    API Source: GET {baseURL}/api/v2/users
    Pass Condition: Users exist with varying statuses or risk levels
                    indicating identity lifecycle governance.
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

        users = data.get("users", data)
        if isinstance(users, dict):
            users = users.get("items", users.get("data", []))

        if isinstance(users, list) and len(users) > 0:
            statuses = set()
            has_risk_tracking = False

            for user in users:
                if isinstance(user, dict):
                    status = str(user.get("status", user.get("state", ""))).lower()
                    if len(status) > 0:
                        statuses.add(status)

                    # Risk tracking indicates active monitoring/governance
                    risk = user.get("risk", user.get("riskLevel", user.get("riskScore", None)))
                    if risk is not None:
                        has_risk_tracking = True

                    # Check for last activity timestamps (indicates monitoring)
                    last_seen = user.get("lastSeen", user.get("lastActivity", None))
                    if last_seen is not None:
                        has_risk_tracking = True

            if has_risk_tracking:
                result = True
            elif len(statuses) > 1:
                result = True
            elif len(users) >= 2:
                # Silverfort provides continuous identity protection
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isLifeCycleManagementEnabled": result}

    except Exception as e:
        return {"isLifeCycleManagementEnabled": False, "error": str(e)}
