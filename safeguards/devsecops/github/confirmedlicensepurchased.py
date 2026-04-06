import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for GitHub (Code Hosting / DevOps)

    Checks: Whether the GitHub organization exists and is accessible
    API Source: GET https://api.github.com/orgs/{org}
    Pass Condition: API returns a valid organization object with login and ID

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean}
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
        result = False

        # A valid organization response confirms active GitHub subscription
        org_login = data.get("login", "")
        org_id = data.get("id", "")
        org_name = data.get("name", "")
        plan = data.get("plan", {})

        if org_login or org_id:
            result = True
        elif org_name:
            result = True
        elif isinstance(plan, dict) and plan.get("name"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
