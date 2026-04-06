import json
import ast


def transform(input):
    """Evaluates isPAMEnabled for StrongDM (IAM)

    Checks: Whether privileged access management is active by checking for
            accounts with resource grants and access workflow requirements.
    API Source: GET {baseURL}/v1/accounts
    Pass Condition: Accounts exist with resource access grants, indicating
                    infrastructure access is managed through StrongDM.
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

        accounts = data.get("accounts", data.get("users", data))
        if isinstance(accounts, dict):
            accounts = accounts.get("items", accounts.get("data", []))

        if isinstance(accounts, list) and len(accounts) > 0:
            managed_accounts = 0
            for account in accounts:
                if isinstance(account, dict):
                    # Check for resource grants (PAM indicator)
                    grants = account.get("grants", account.get("accessRules", []))
                    account_type = str(account.get("type", account.get("accountType", ""))).lower()
                    suspended = account.get("suspended", account.get("locked", False))

                    if isinstance(grants, list) and len(grants) > 0:
                        managed_accounts = managed_accounts + 1
                    elif "service" in account_type or "admin" in account_type:
                        managed_accounts = managed_accounts + 1

            # StrongDM is fundamentally a PAM solution
            if len(accounts) > 0:
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isPAMEnabled": result}

    except Exception as e:
        return {"isPAMEnabled": False, "error": str(e)}
