import json
import ast


def transform(input):
    """
    Evaluates isPAMEnabled for Active Directory On-Prem (IAM)

    Checks: Whether privileged accounts (Domain Admins, Enterprise Admins) are managed and limited
    API Source: GET {baseURL}/api/users
    Pass Condition: Privileged admin accounts are identified and their count is limited relative to total users
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

        users = data.get("users", data.get("data", data.get("value", [])))
        if isinstance(users, list) and len(users) > 0:
            total_count = len(users)
            # Identify privileged users by admin group membership or admin flag
            admin_users = []
            for user in users:
                is_admin = user.get("isAdmin", user.get("adminAccount", False))
                groups = user.get("memberOf", user.get("groups", []))
                if isinstance(groups, list):
                    admin_groups = [
                        g for g in groups
                        if any(keyword in str(g).lower() for keyword in ["domain admin", "enterprise admin", "schema admin", "administrator"])
                    ]
                    if admin_groups or is_admin:
                        admin_users.append(user)
                elif is_admin:
                    admin_users.append(user)

            # PAM is considered enabled if admin accounts exist and are limited
            # (less than 10% of total users or fewer than 10 admin accounts)
            if len(admin_users) > 0 and (len(admin_users) < total_count * 0.1 or len(admin_users) <= 10):
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isPAMEnabled": result}

    except Exception as e:
        return {"isPAMEnabled": False, "error": str(e)}
