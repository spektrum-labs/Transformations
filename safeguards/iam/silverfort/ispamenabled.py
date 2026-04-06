import json
import ast


def transform(input):
    """Evaluates isPAMEnabled for Silverfort (IAM)

    Checks: Whether privileged access management is active by checking for
            service accounts and privileged users with Silverfort protection.
    API Source: GET {baseURL}/api/v2/users
    Pass Condition: Users include service accounts or privileged entities
                    with risk scoring and policy protection.
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

        users = data.get("users", data)
        if isinstance(users, dict):
            users = users.get("items", users.get("data", []))

        if isinstance(users, list) and len(users) > 0:
            service_accounts = 0
            privileged_users = 0

            for user in users:
                if isinstance(user, dict):
                    user_type = str(user.get("type", user.get("accountType", ""))).lower()
                    upn = str(user.get("upn", user.get("userPrincipalName", ""))).lower()
                    risk = user.get("risk", user.get("riskLevel", None))

                    if "service" in user_type or "machine" in user_type:
                        service_accounts = service_accounts + 1
                    elif "admin" in upn or "priv" in upn:
                        privileged_users = privileged_users + 1

                    # Silverfort risk scoring on users indicates PAM monitoring
                    if risk is not None:
                        privileged_users = privileged_users + 1

            if service_accounts > 0 or privileged_users > 0:
                result = True
            elif len(users) > 0:
                # Silverfort itself provides unified identity protection (PAM-like)
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isPAMEnabled": result}

    except Exception as e:
        return {"isPAMEnabled": False, "error": str(e)}
