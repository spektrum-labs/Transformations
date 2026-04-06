import json
import ast


def transform(input):
    """Evaluates isLifeCycleManagementEnabled for OneLogin (IAM)

    Validates lifecycle management by checking user status fields
    (active, suspended, locked) and provisioning state in OneLogin.

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
        if isinstance(users, list) and len(users) > 0:
            managed_count = 0
            for user in users:
                # OneLogin status codes: 0=Unactivated, 1=Active, 2=Suspended,
                # 3=Locked, 4=Password expired, 5=Awaiting password reset
                status = user.get("status", None)
                created_at = user.get("created_at", "")
                updated_at = user.get("updated_at", "")
                if status is not None and status in (0, 2, 3, 4, 5):
                    managed_count += 1
                elif created_at or updated_at:
                    managed_count += 1
            result = managed_count > 0
        # ── END EVALUATION LOGIC ──

        return {"isLifeCycleManagementEnabled": result}

    except Exception as e:
        return {"isLifeCycleManagementEnabled": False, "error": str(e)}
