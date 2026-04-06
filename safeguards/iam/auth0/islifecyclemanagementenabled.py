import json
import ast


def transform(input):
    """
    Evaluates isLifeCycleManagementEnabled for Auth0 (IAM)

    Checks: Whether proper user provisioning and deprovisioning processes exist
    API Source: GET {baseURL}/api/v2/users
    Pass Condition: Evidence of lifecycle management via blocked users or email verification enforcement
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

        users = data if isinstance(data, list) else data.get("users", data.get("data", []))

        if isinstance(users, list) and len(users) > 0:
            has_blocked = False
            has_verification = False

            for user in users:
                # Check for blocked (deprovisioned) users
                if user.get("blocked", False) is True:
                    has_blocked = True
                # Check for email verification enforcement
                if user.get("email_verified") is not None:
                    has_verification = True

            # Lifecycle management is active if there is evidence of account state management
            result = has_blocked or has_verification
        # ── END EVALUATION LOGIC ──

        return {"isLifeCycleManagementEnabled": result}

    except Exception as e:
        return {"isLifeCycleManagementEnabled": False, "error": str(e)}
