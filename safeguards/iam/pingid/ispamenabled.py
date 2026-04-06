import json
import ast


def transform(input):
    """Evaluates isPAMEnabled for PingID / PingOne (IAM)

    Validates that privileged access controls are in place by checking
    user account types and admin role assignments in PingOne.

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

        embedded = data.get("_embedded", data)
        users = embedded.get("users", data.get("users", []))

        if isinstance(users, list) and len(users) > 0:
            privileged_count = 0
            for user in users:
                account_type = user.get("type", "")
                membership = user.get("memberOfRoleAssignments", user.get("roleAssignments", []))
                if isinstance(account_type, str) and account_type.upper() in ("ADMIN", "ENVIRONMENT_ADMIN"):
                    privileged_count += 1
                elif isinstance(membership, list) and len(membership) > 0:
                    privileged_count += 1
            result = privileged_count > 0
        # ── END EVALUATION LOGIC ──

        return {"isPAMEnabled": result}

    except Exception as e:
        return {"isPAMEnabled": False, "error": str(e)}
