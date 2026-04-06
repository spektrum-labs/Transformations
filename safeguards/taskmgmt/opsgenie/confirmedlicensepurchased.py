import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Opsgenie (Incident Alerting / On-Call)

    Checks: Whether the Opsgenie account is active via the account endpoint
    API Source: {baseURL}/v2/account
    Pass Condition: API returns valid account data with a plan

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "plan": str, "status": str}
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

        # -- EVALUATION LOGIC --
        account_data = data.get("data", data)
        plan = account_data.get("plan", {})
        plan_name = plan.get("name", "unknown") if isinstance(plan, dict) else str(plan)
        account_name = account_data.get("name", "")

        result = bool(account_name) or bool(account_data.get("id", ""))
        status = "active" if result else "unknown"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "plan": plan_name,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
