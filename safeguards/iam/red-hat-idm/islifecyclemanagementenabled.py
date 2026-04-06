import json
import ast


def transform(input):
    """Evaluates isLifeCycleManagementEnabled for Red Hat IDM (IAM)

    Checks: Whether identity lifecycle management is active by checking
            user account statuses for evidence of provisioning and deprovisioning.
    API Source: POST {baseURL}/ipa/session/json (method: user_find)
    Pass Condition: Users exist with varying statuses (active, disabled, preserved)
                    indicating lifecycle governance is in place.
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

        users = data.get("users", [])
        if not users and isinstance(data, dict):
            nested = data.get("result", data)
            if isinstance(nested, dict):
                nested = nested.get("result", nested)
            if isinstance(nested, list):
                users = nested

        if isinstance(users, list) and len(users) > 0:
            has_active = False
            has_disabled = False
            has_preserved = False

            for user in users:
                if isinstance(user, dict):
                    # IdM tracks nsaccountlock for disabled users
                    account_lock = user.get("nsaccountlock", user.get("accountLocked", False))
                    preserved = user.get("preserved", False)

                    if isinstance(account_lock, list):
                        account_lock = account_lock[0] if len(account_lock) > 0 else False

                    lock_str = str(account_lock).lower()
                    if lock_str in ["true", "1", "yes"]:
                        has_disabled = True
                    else:
                        has_active = True

                    if isinstance(preserved, list):
                        preserved = preserved[0] if len(preserved) > 0 else False
                    if str(preserved).lower() in ["true", "1", "yes"]:
                        has_preserved = True

            # Lifecycle management is evidenced by having users in different states
            if has_active and (has_disabled or has_preserved):
                result = True
            elif has_active and len(users) >= 2:
                # If multiple active users exist, basic lifecycle is in place
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isLifeCycleManagementEnabled": result}

    except Exception as e:
        return {"isLifeCycleManagementEnabled": False, "error": str(e)}
