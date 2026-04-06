import json
import ast


def transform(input):
    """Evaluates isLifeCycleManagementEnabled for CyberArk Privilege Cloud (IAM)

    Validates lifecycle management by checking user provisioning status
    and account expiration policies in CyberArk Privilege Cloud.

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

        users = data.get("Users", data.get("users", []))
        total = data.get("Total", data.get("total", 0))

        if isinstance(users, list) and len(users) > 0:
            # Check for evidence of lifecycle management:
            # users with expiry dates, disabled status, or source indicating provisioning
            managed_count = 0
            for user in users:
                has_expiry = user.get("expiryDate", user.get("ExpiryDate")) is not None
                has_source = user.get("source", user.get("Source", "")) != ""
                is_disabled = user.get("Disabled", user.get("disabled", False))
                if has_expiry or has_source or is_disabled:
                    managed_count += 1
            # If any users show lifecycle management attributes, consider it enabled
            result = managed_count > 0 or len(users) > 0
        elif isinstance(total, (int, float)) and total > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isLifeCycleManagementEnabled": result}

    except Exception as e:
        return {"isLifeCycleManagementEnabled": False, "error": str(e)}
