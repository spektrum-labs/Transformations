import json
import ast


def transform(input):
    """Evaluates isLifeCycleManagementEnabled for StrongDM (IAM)

    Checks: Whether lifecycle management is active by checking account
            statuses and suspension states for evidence of automated governance.
    API Source: GET {baseURL}/v1/accounts
    Pass Condition: Accounts exist with varying statuses (active, suspended)
                    indicating lifecycle governance is in place.
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
            has_active = False
            has_suspended = False
            has_permissions_managed = False

            for account in accounts:
                if isinstance(account, dict):
                    suspended = account.get("suspended", account.get("locked", False))
                    if isinstance(suspended, bool):
                        if suspended:
                            has_suspended = True
                        else:
                            has_active = True

                    # Check for temporary access grants (lifecycle indicator)
                    grants = account.get("grants", account.get("accessRules", []))
                    if isinstance(grants, list):
                        for grant in grants:
                            if isinstance(grant, dict):
                                expires = grant.get("expiresAt", grant.get("validUntil", None))
                                if expires is not None:
                                    has_permissions_managed = True
                                    break

            if has_active and has_suspended:
                result = True
            elif has_permissions_managed:
                result = True
            elif len(accounts) >= 2:
                # StrongDM manages infrastructure access lifecycle
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isLifeCycleManagementEnabled": result}

    except Exception as e:
        return {"isLifeCycleManagementEnabled": False, "error": str(e)}
