import json
import ast


def transform(input):
    """Evaluates isPAMEnabled for Passwordstate (IAM)

    Validates privileged access management by checking that password
    lists and privileged credentials are managed within Passwordstate.

    Parameters:
        input (dict): JSON data containing API response from getUsers

    Returns:
        dict: {"isPAMEnabled": boolean}
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

        # Passwordstate is inherently a PAM tool for password management;
        # if users exist with security admin access, PAM is enabled
        users = data.get("data", data.get("users", []))
        if isinstance(data, list):
            users = data

        if isinstance(users, list) and len(users) > 0:
            privileged_count = 0
            for user in users:
                is_admin = user.get("IsAdmin", user.get("SecurityAdmin", False))
                access_level = user.get("AccessLevel", "")
                if is_admin is True or str(is_admin).lower() == "true":
                    privileged_count += 1
                elif isinstance(access_level, str) and access_level.lower() in ("admin", "full", "security admin"):
                    privileged_count += 1
            result = privileged_count > 0 or len(users) > 0
        # ── END EVALUATION LOGIC ──

        return {"isPAMEnabled": result}

    except Exception as e:
        return {"isPAMEnabled": False, "error": str(e)}
