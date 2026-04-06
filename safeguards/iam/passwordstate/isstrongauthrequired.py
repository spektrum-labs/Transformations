import json
import ast


def transform(input):
    """Evaluates isStrongAuthRequired for Passwordstate (IAM)

    Checks that Passwordstate users have multi-factor authentication
    configured by inspecting security settings on user accounts.

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

        users = data.get("data", data.get("users", []))
        if isinstance(data, list):
            users = data

        if isinstance(users, list) and len(users) > 0:
            mfa_count = 0
            total_active = 0
            for user in users:
                # Check if user is enabled
                is_enabled = user.get("EnableUser", user.get("IsEnabled", True))
                if not is_enabled:
                    continue
                total_active += 1
                # Check for MFA/2FA settings
                mfa_enabled = user.get("MFAEnabled", user.get("TwoFactorEnabled", False))
                auth_type = user.get("AuthenticationType", "")
                if mfa_enabled is True or str(mfa_enabled).lower() == "true":
                    mfa_count += 1
                elif isinstance(auth_type, str) and auth_type.lower() not in ("", "password", "windows"):
                    mfa_count += 1
            if total_active > 0:
                result = mfa_count >= total_active * 0.5
        # ── END EVALUATION LOGIC ──

        return {"isStrongAuthRequired": result}

    except Exception as e:
        return {"isStrongAuthRequired": False, "error": str(e)}
