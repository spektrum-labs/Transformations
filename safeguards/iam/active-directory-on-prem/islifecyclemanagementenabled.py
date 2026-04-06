import json
import ast


def transform(input):
    """
    Evaluates isLifeCycleManagementEnabled for Active Directory On-Prem (IAM)

    Checks: Whether disabled and expired accounts are handled through proper lifecycle processes
    API Source: GET {baseURL}/api/users
    Pass Condition: Evidence of account lifecycle management (disabled accounts, expiration dates set)
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

        users = data.get("users", data.get("data", data.get("value", [])))
        if isinstance(users, list) and len(users) > 0:
            # Check for lifecycle indicators: disabled accounts, expiration dates, last logon tracking
            has_disabled = False
            has_expiration = False
            has_last_logon = False

            for user in users:
                enabled = user.get("enabled", user.get("isEnabled", user.get("userAccountControl", None)))
                if enabled is False or str(enabled) == "False":
                    has_disabled = True
                expiry = user.get("accountExpires", user.get("expirationDate", user.get("accountExpirationDate", None)))
                if expiry is not None and str(expiry) not in ("0", "never", "", "None"):
                    has_expiration = True
                last_logon = user.get("lastLogon", user.get("lastLogonTimestamp", user.get("lastLogin", None)))
                if last_logon is not None:
                    has_last_logon = True

            # Lifecycle management is active if there are disabled accounts or expiration policies
            result = has_disabled or has_expiration
        # ── END EVALUATION LOGIC ──

        return {"isLifeCycleManagementEnabled": result}

    except Exception as e:
        return {"isLifeCycleManagementEnabled": False, "error": str(e)}
