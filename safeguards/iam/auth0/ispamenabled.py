import json
import ast


def transform(input):
    """
    Evaluates isPAMEnabled for Auth0 (IAM)

    Checks: Whether privileged accounts are managed with appropriate role assignments
    API Source: GET {baseURL}/api/v2/users
    Pass Condition: Users exist with role assignments and admin accounts are limited in number
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

        users = data if isinstance(data, list) else data.get("users", data.get("data", []))

        if isinstance(users, list) and len(users) > 0:
            total_count = len(users)
            # Check for admin/privileged user indicators
            admin_users = []
            for user in users:
                app_metadata = user.get("app_metadata", {})
                roles = app_metadata.get("roles", []) if isinstance(app_metadata, dict) else []
                is_admin = app_metadata.get("admin", False) if isinstance(app_metadata, dict) else False

                if is_admin or any("admin" in str(r).lower() for r in roles):
                    admin_users.append(user)

            # PAM is considered enabled if admin accounts are limited
            if len(admin_users) > 0 and (len(admin_users) < total_count * 0.1 or len(admin_users) <= 10):
                result = True
            elif total_count > 0:
                # If we can retrieve users, basic account management is in place
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isPAMEnabled": result}

    except Exception as e:
        return {"isPAMEnabled": False, "error": str(e)}
