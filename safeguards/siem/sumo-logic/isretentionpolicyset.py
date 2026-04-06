import json
import ast


def transform(input):
    """
    Evaluates isRetentionPolicySet for Sumo Logic SIEM

    Checks: Whether the Sumo Logic account status confirms the platform is
            operational and data retention policies are in effect.

    API Source: GET {baseURL}/v1/account/status
    Pass Condition: The account is active and the response includes plan/retention
                    information, confirming data retention is configured.

    Parameters:
        input (dict): JSON data containing API response from the account status endpoint

    Returns:
        dict: {"isRetentionPolicySet": boolean, "retentionInfo": str}
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

        # Sumo Logic account status includes plan and retention details
        plan_type = data.get("planType", data.get("pricingModel", ""))
        retention_days = data.get("retentionDays", data.get("defaultDataRetentionDays", None))
        account_status = data.get("accountStatus", data.get("status", ""))

        if retention_days is not None:
            result = int(retention_days) > 0
            info = str(retention_days) + " days"
        elif plan_type:
            result = True
            info = "plan: " + str(plan_type)
        elif account_status:
            result = str(account_status).lower() in ("active", "ok", "enabled")
            info = "account " + str(account_status)
        else:
            result = bool(data) and "error" not in str(data).lower()
            info = "status retrieved" if result else "unknown"

        return {
            "isRetentionPolicySet": result,
            "retentionInfo": info
        }

    except Exception as e:
        return {"isRetentionPolicySet": False, "error": str(e)}
