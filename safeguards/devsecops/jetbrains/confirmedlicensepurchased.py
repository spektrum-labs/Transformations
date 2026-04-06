import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for JetBrains Space

    Checks: Whether the JetBrains Space organization is active
    API Source: {baseURL}/api/http/organization
    Pass Condition: Organization exists and is accessible

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
        name = data.get("name", "")
        org_id = data.get("id", "")
        plan = data.get("plan", data.get("subscription", {}).get("plan", "unknown"))

        if isinstance(plan, dict):
            plan = plan.get("name", "unknown")

        result = bool(name) or bool(org_id)
        status = "active" if result else "inactive"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "plan": plan,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
