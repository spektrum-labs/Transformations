import json
import ast


def transform(input):
    """Evaluates isStrongAuthRequired for JumpCloud (IAM)

    Checks that MFA is enabled for JumpCloud users by inspecting
    the mfa and totp configuration fields on system user records.

    Parameters:
        input (dict): JSON data containing API response from getEstateMFAStatus

    Returns:
        dict: {"isStrongAuthRequired": boolean}
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

        users = data.get("results", data.get("users", []))
        if isinstance(users, list) and len(users) > 0:
            mfa_enabled_count = 0
            total_active = 0
            for user in users:
                # Skip suspended/locked users
                state = user.get("state", user.get("account_locked", ""))
                if str(state).lower() in ("suspended", "locked"):
                    continue
                total_active += 1
                mfa = user.get("mfa", {})
                totp_enabled = user.get("enable_user_portal_multifactor", False)
                if isinstance(mfa, dict) and mfa.get("configured", False):
                    mfa_enabled_count += 1
                elif totp_enabled is True or str(totp_enabled).lower() == "true":
                    mfa_enabled_count += 1
            # MFA is strong if majority of active users have it enabled
            if total_active > 0:
                result = mfa_enabled_count >= total_active * 0.5
        # ── END EVALUATION LOGIC ──

        return {"isStrongAuthRequired": result}

    except Exception as e:
        return {"isStrongAuthRequired": False, "error": str(e)}
