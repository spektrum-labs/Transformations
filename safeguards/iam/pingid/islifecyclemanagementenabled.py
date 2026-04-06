import json
import ast


def transform(input):
    """Evaluates isLifeCycleManagementEnabled for PingID / PingOne (IAM)

    Validates lifecycle management by checking user status fields
    (ENABLED, DISABLED) and account creation/update timestamps in PingOne.

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

        embedded = data.get("_embedded", data)
        users = embedded.get("users", data.get("users", []))

        if isinstance(users, list) and len(users) > 0:
            managed_count = 0
            for user in users:
                enabled = user.get("enabled", user.get("status", {}).get("enabled", None))
                lifecycle = user.get("lifecycle", {})
                created_at = user.get("createdAt", user.get("created_at", ""))
                updated_at = user.get("updatedAt", user.get("updated_at", ""))
                # Check for disabled users (lifecycle managed)
                if enabled is False:
                    managed_count += 1
                elif isinstance(lifecycle, dict) and lifecycle.get("status", ""):
                    managed_count += 1
                elif created_at or updated_at:
                    managed_count += 1
            result = managed_count > 0
        # ── END EVALUATION LOGIC ──

        return {"isLifeCycleManagementEnabled": result}

    except Exception as e:
        return {"isLifeCycleManagementEnabled": False, "error": str(e)}
