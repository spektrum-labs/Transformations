import json
import ast


def _parse_input(input):
    if isinstance(input, str):
        try:
            parsed = ast.literal_eval(input)
            if isinstance(parsed, dict):
                return parsed
        except:
            pass
        try:
            input = input.replace("'", '"')
            return json.loads(input)
        except:
            raise ValueError("Input string is neither valid Python literal nor JSON")
    if isinstance(input, bytes):
        return json.loads(input.decode("utf-8"))
    if isinstance(input, dict):
        return input
    raise ValueError("Input must be JSON string, bytes, or dict")


def transform(input):
    """
    Verifies MFA is enabled for DNSFilter admin accounts

    Parameters:
        input (dict): Users data from GET /users

    Returns:
        dict: {"isMFAEnabled": boolean, "usersWithMFA": int, "totalAdmins": int}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        users = data if isinstance(data, list) else data.get("users", [])

        if not users:
            return {"isMFAEnabled": False, "error": "No users found"}

        admin_users = []
        mfa_enabled_count = 0

        for user in users:
            permissions = user.get("permissions", {})
            role = permissions.get("role", "").lower()

            # Check for admin-level users
            if role in ("admin", "owner", "super_admin", "administrator"):
                admin_users.append(user)
                if user.get("mfa_enabled", False):
                    mfa_enabled_count += 1

        # If no explicit admins found, check all users
        if not admin_users:
            admin_users = users
            mfa_enabled_count = sum(1 for u in users if u.get("mfa_enabled", False))

        total_admins = len(admin_users)

        # All admin users must have MFA enabled
        all_mfa_enabled = mfa_enabled_count == total_admins and total_admins > 0

        return {
            "isMFAEnabled": all_mfa_enabled,
            "usersWithMFA": mfa_enabled_count,
            "totalAdmins": total_admins
        }

    except Exception as e:
        return {"isMFAEnabled": False, "error": str(e)}
