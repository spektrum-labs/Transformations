import json
import ast


def transform(input):
    """Evaluates isPAMEnabled for JumpCloud (IAM)

    Validates that user accounts have appropriate privilege controls
    such as sudo permissions and admin flags managed through JumpCloud.

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

        users = data.get("results", data.get("users", []))
        if isinstance(users, list) and len(users) > 0:
            # Check if any users have sudo or admin privileges managed
            privileged_count = 0
            for user in users:
                sudo = user.get("sudo", False)
                admin = user.get("admin", user.get("administrator", False))
                if sudo is True or admin is True:
                    privileged_count += 1
            # PAM is enabled if there are managed privileged accounts
            result = privileged_count > 0
        # ── END EVALUATION LOGIC ──

        return {"isPAMEnabled": result}

    except Exception as e:
        return {"isPAMEnabled": False, "error": str(e)}
