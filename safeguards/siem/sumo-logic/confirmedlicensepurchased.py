import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Sumo Logic SIEM

    Checks: Whether the Sumo Logic account is active by checking the account
            status endpoint for a valid, non-suspended account state.

    API Source: GET {baseURL}/v1/account/status
    Pass Condition: The account status response indicates an active, non-suspended
                    account, confirming a valid Sumo Logic subscription.

    Parameters:
        input (dict): JSON data containing API response from the account status endpoint

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "accountStatus": str, "planType": str}
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

        # Standard response unwrapping chain
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # Sumo Logic account status returns plan and status info
        account_status = data.get("accountStatus", data.get("status", ""))
        plan_type = data.get("planType", data.get("pricingModel", ""))
        can_manage = data.get("canManageAccount", None)

        if account_status:
            result = str(account_status).lower() in ("active", "ok", "enabled")
        elif can_manage is not None:
            result = True  # If we get account management info, account is active
        else:
            result = bool(data) and "error" not in str(data).lower()

        return {
            "confirmedLicensePurchased": result,
            "accountStatus": str(account_status) if account_status else "unknown",
            "planType": str(plan_type) if plan_type else "unknown"
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
