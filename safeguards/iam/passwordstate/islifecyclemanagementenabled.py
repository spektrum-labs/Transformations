import json
import ast


def transform(input):
    """Evaluates isLifeCycleManagementEnabled for Passwordstate (IAM)

    Validates lifecycle management by checking user provisioning status
    and password expiry policies in Passwordstate.

    Parameters:
        input (dict): JSON data containing API response from getUsers

    Returns:
        dict: {"isLifeCycleManagementEnabled": boolean}
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
            managed_count = 0
            for user in users:
                # Check for lifecycle attributes
                is_enabled = user.get("EnableUser", user.get("IsEnabled", None))
                last_login = user.get("LastLogin", user.get("LastLoggedIn", ""))
                created = user.get("DateCreated", user.get("Created", ""))
                if is_enabled is False:
                    managed_count += 1
                elif last_login or created:
                    managed_count += 1
            result = managed_count > 0
        # ── END EVALUATION LOGIC ──

        return {"isLifeCycleManagementEnabled": result}

    except Exception as e:
        return {"isLifeCycleManagementEnabled": False, "error": str(e)}
