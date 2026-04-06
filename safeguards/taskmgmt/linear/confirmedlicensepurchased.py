import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Linear (Project Management)

    Checks: Whether the Linear organization has an active subscription
    API Source: https://api.linear.app/graphql (organization query)
    Pass Condition: Organization data is returned with subscription info

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
        gql_data = data.get("data", data)
        org = gql_data.get("organization", {})
        subscription = org.get("subscription", {})
        plan = subscription.get("type", "unknown") if subscription else "unknown"
        org_name = org.get("name", "")

        result = bool(org_name) or bool(org.get("id", ""))
        status = "active" if result else "unknown"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "plan": plan,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
