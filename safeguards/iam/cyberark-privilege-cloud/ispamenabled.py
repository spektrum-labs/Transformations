import json
import ast


def transform(input):
    """Evaluates isPAMEnabled for CyberArk Privilege Cloud (IAM)

    Validates that privileged access management is active by checking for
    managed vault users and privileged accounts in CyberArk Privilege Cloud.

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

        # CyberArk Privilege Cloud is inherently a PAM solution;
        # if users exist in the vault, PAM is enabled
        users = data.get("Users", data.get("users", []))
        total = data.get("Total", data.get("total", 0))

        if isinstance(users, list) and len(users) > 0:
            result = True
        elif isinstance(total, (int, float)) and total > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isPAMEnabled": result}

    except Exception as e:
        return {"isPAMEnabled": False, "error": str(e)}
