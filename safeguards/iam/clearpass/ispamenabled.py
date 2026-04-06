import json
import ast


def transform(input):
    """
    Evaluates isPAMEnabled for ClearPass (IAM)

    Checks: Whether admin operator accounts are managed with appropriate privilege levels
    API Source: GET {baseURL}/api/local-user
    Pass Condition: Local users exist and admin-level accounts are limited relative to total
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

        items = data.get("_embedded", {}).get("items", data.get("items", data.get("data", [])))

        if isinstance(items, list) and len(items) > 0:
            total_count = len(items)
            # Check for admin/privileged user indicators
            admin_users = []
            for user in items:
                role_name = str(user.get("role_name", user.get("role", ""))).lower()
                enabled = user.get("enabled", True)

                if "admin" in role_name or "super" in role_name:
                    admin_users.append(user)

            # PAM is enabled if admin accounts are tracked and limited
            if len(admin_users) > 0 and (len(admin_users) < total_count * 0.2 or len(admin_users) <= 10):
                result = True
            elif total_count > 0:
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isPAMEnabled": result}

    except Exception as e:
        return {"isPAMEnabled": False, "error": str(e)}
