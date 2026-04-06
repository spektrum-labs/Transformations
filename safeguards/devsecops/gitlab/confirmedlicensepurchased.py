import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for GitLab

    Checks: Whether the GitLab instance has an active license or subscription
    API Source: {baseURL}/api/v4/license
    Pass Condition: License exists and has not expired

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
        plan = data.get("plan", data.get("type", "unknown"))
        expired = data.get("expired", True)
        active_users = data.get("active_users", 0)

        if isinstance(plan, str):
            plan = plan.lower()

        result = not expired and active_users > 0
        status = "active" if result else "expired"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "plan": plan,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
