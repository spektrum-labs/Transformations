import json
import ast


def transform(input):
    """Evaluates isLifeCycleManagementEnabled for JumpCloud (IAM)

    Validates lifecycle management by checking user account states including
    activated, suspended, and account lock status fields.

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

        users = data.get("results", data.get("users", []))
        if isinstance(users, list) and len(users) > 0:
            # Check for lifecycle indicators: suspended users, locked accounts,
            # or users with activation/created timestamps
            managed_count = 0
            for user in users:
                state = user.get("state", "")
                account_locked = user.get("account_locked", False)
                suspended = user.get("suspended", False)
                created = user.get("created", user.get("_created", ""))
                if state in ("SUSPENDED", "STAGED", "LOCKED_OUT"):
                    managed_count += 1
                elif account_locked is True or suspended is True:
                    managed_count += 1
                elif created:
                    managed_count += 1
            # If users have lifecycle attributes, management is enabled
            result = managed_count > 0
        # ── END EVALUATION LOGIC ──

        return {"isLifeCycleManagementEnabled": result}

    except Exception as e:
        return {"isLifeCycleManagementEnabled": False, "error": str(e)}
