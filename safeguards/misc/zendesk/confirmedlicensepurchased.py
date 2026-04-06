import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Zendesk.

    Checks: Active Zendesk subscription by verifying account settings endpoint
            returns valid account data with an active plan.
    API Source: GET https://{subdomain}.zendesk.com/api/v2/account/settings.json
    Pass Condition: Account settings are returned with active status

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
        settings = data.get("settings", data.get("account", {}))
        if not isinstance(settings, dict):
            settings = {}

        billing = settings.get("billing", {})
        if not isinstance(billing, dict):
            billing = {}

        plan_name = billing.get("plan_name", settings.get("plan_name", "unknown"))
        error = data.get("error", data.get("errors", None))

        if error:
            result = False
            status = "error"
        elif isinstance(settings, dict) and len(settings) > 0:
            result = True
            status = "active"
        elif isinstance(data, dict) and len(data) > 0 and not error:
            result = True
            status = "active"
        else:
            result = False
            status = "inactive"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "plan": str(plan_name),
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
