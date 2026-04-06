import json
import ast


def transform(input):
    """Evaluates isPAMEnabled for OneLogin (IAM)

    Validates that privileged access controls exist by checking user
    roles and admin privilege assignments in OneLogin.

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

        users = data.get("data", data.get("users", []))
        if isinstance(users, list) and len(users) > 0:
            privileged_count = 0
            for user in users:
                role_ids = user.get("role_ids", user.get("role_id", []))
                is_admin = user.get("is_admin", user.get("admin", False))
                if isinstance(role_ids, list) and len(role_ids) > 0:
                    privileged_count += 1
                elif is_admin is True:
                    privileged_count += 1
            result = privileged_count > 0
        # ── END EVALUATION LOGIC ──

        return {"isPAMEnabled": result}

    except Exception as e:
        return {"isPAMEnabled": False, "error": str(e)}
