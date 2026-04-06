import json
import ast


def transform(input):
    """
    Evaluates isPAMEnabled for Authentik (IAM)

    Checks: Whether privileged accounts are managed with superuser flags and admin group membership
    API Source: GET {baseURL}/api/v3/core/users/
    Pass Condition: Superuser accounts are identified and limited relative to total users
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

        users = data.get("results", data.get("data", []))

        if isinstance(users, list) and len(users) > 0:
            total_count = len(users)
            # Authentik uses is_superuser flag for privileged accounts
            superusers = [u for u in users if u.get("is_superuser", False) is True]

            # PAM is considered enabled if superuser accounts are tracked and limited
            if len(superusers) > 0 and (len(superusers) < total_count * 0.1 or len(superusers) <= 10):
                result = True
            elif total_count > 0 and len(superusers) == 0:
                # No superusers in the response set suggests proper privilege management
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isPAMEnabled": result}

    except Exception as e:
        return {"isPAMEnabled": False, "error": str(e)}
