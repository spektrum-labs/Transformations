import json
import ast


def transform(input):
    """Evaluates isStrongAuthRequired for CyberArk Privilege Cloud (IAM)

    Checks whether MFA or strong authentication is enforced for CyberArk
    users by inspecting authentication method configurations.

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

        users = data.get("Users", data.get("users", []))
        if isinstance(users, list) and len(users) > 0:
            # Check if users have authentication methods requiring MFA
            mfa_count = 0
            for user in users:
                auth_methods = user.get("authenticationMethod", user.get("AuthenticationMethod", []))
                enable_user = user.get("enableUser", user.get("Disabled", False))
                # Skip disabled users
                if enable_user is True or str(enable_user).lower() == "true":
                    continue
                if isinstance(auth_methods, list) and len(auth_methods) > 0:
                    mfa_count += 1
                elif isinstance(auth_methods, str) and auth_methods.lower() not in ("", "password"):
                    mfa_count += 1
            # If more than half of active users have strong auth, consider it enforced
            result = mfa_count > 0 and mfa_count >= len(users) * 0.5
        # ── END EVALUATION LOGIC ──

        return {"isStrongAuthRequired": result}

    except Exception as e:
        return {"isStrongAuthRequired": False, "error": str(e)}
