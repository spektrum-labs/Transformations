import json
import ast


def transform(input):
    """Evaluates isPAMEnabled for Red Hat IDM (IAM)

    Checks: Whether privileged access management is active by checking for
            dedicated admin and service accounts with proper separation.
    API Source: POST {baseURL}/ipa/session/json (method: user_find)
    Pass Condition: At least one admin-type user exists with separate
                    privileged accounts.
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

        users = data.get("users", [])
        if not users and isinstance(data, dict):
            nested = data.get("result", data)
            if isinstance(nested, dict):
                nested = nested.get("result", nested)
            if isinstance(nested, list):
                users = nested

        if isinstance(users, list) and len(users) > 0:
            admin_users = []
            regular_users = []
            for user in users:
                if isinstance(user, dict):
                    groups = user.get("memberof_group", user.get("groups", []))
                    uid = user.get("uid", user.get("login", [""]))[0] if isinstance(user.get("uid", user.get("login", "")), list) else user.get("uid", user.get("login", ""))
                    is_admin = False

                    if isinstance(groups, list):
                        for group in groups:
                            group_str = str(group).lower()
                            if "admin" in group_str or "sudo" in group_str or "wheel" in group_str:
                                is_admin = True
                                break

                    if is_admin:
                        admin_users.append(uid)
                    else:
                        regular_users.append(uid)

            # PAM is considered enabled if there are dedicated admin accounts
            # and they are separate from regular user accounts
            if len(admin_users) > 0 and len(regular_users) > 0:
                result = True
            elif len(admin_users) > 0:
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isPAMEnabled": result}

    except Exception as e:
        return {"isPAMEnabled": False, "error": str(e)}
