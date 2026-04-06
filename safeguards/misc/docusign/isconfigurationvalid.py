import json
import ast


def transform(input):
    """
    Evaluates isConfigurationValid for DocuSign (Electronic Signatures)

    Checks: Whether the DocuSign account settings are accessible
    API Source: GET {baseURL}/v2.1/accounts/{accountId}
    Pass Condition: API returns valid account configuration with plan and billing info

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isConfigurationValid": boolean}
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

        account_name = data.get("accountName", "")
        plan_id = data.get("currentPlanId", "")
        billing_start = data.get("billingPeriodStartDate", "")

        if account_name and (plan_id or billing_start):
            result = True
        elif account_name:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isConfigurationValid": result}
    except Exception as e:
        return {"isConfigurationValid": False, "error": str(e)}
