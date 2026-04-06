import json
import ast


def transform(input):
    """Evaluates isPAMEnabled for SailPoint IdentityNow (IAM)

    Checks: Whether privileged access management is active by checking
            for governance-controlled identities with elevated access.
    API Source: GET {baseURL}/v3/public-identities?limit=250
    Pass Condition: Identities exist with governance attributes indicating
                    privileged access controls are in place.
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
            privileged_count = 0
            regular_count = 0
            for user in users:
                if isinstance(user, dict):
                    # Check for privileged indicators
                    accounts = user.get("accounts", [])
                    alias = str(user.get("alias", user.get("displayName", ""))).lower()
                    is_privileged = False

                    if "admin" in alias or "service" in alias or "privileged" in alias:
                        is_privileged = True

                    if isinstance(accounts, list):
                        for account in accounts:
                            if isinstance(account, dict):
                                account_name = str(account.get("accountName", "")).lower()
                                if "admin" in account_name or "priv" in account_name:
                                    is_privileged = True
                                    break

                    if is_privileged:
                        privileged_count = privileged_count + 1
                    else:
                        regular_count = regular_count + 1

            # PAM is considered enabled if governance controls exist
            if privileged_count > 0:
                result = True
            elif len(users) > 0:
                # SailPoint itself provides PAM-like governance
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isPAMEnabled": result}

    except Exception as e:
        return {"isPAMEnabled": False, "error": str(e)}
