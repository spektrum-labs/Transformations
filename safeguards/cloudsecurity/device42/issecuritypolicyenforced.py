import json
import ast


def transform(input):
    """
    Evaluates isSecurityPolicyEnforced for Device42

    Checks: Whether custom fields and device management policies are configured
    API Source: {baseURL}/api/1.0/custom_fields/device/
    Pass Condition: At least one custom field policy is defined for device management

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityPolicyEnforced": boolean, "totalCustomFields": int}
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
        fields = data.get("custom_fields", data.get("data", data.get("results", data.get("items", []))))

        if isinstance(fields, list):
            total = len(fields)
        elif isinstance(fields, dict):
            total = fields.get("total_count", fields.get("totalCount", 0))
        else:
            total = 0

        result = total > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityPolicyEnforced": result,
            "totalCustomFields": total
        }

    except Exception as e:
        return {"isSecurityPolicyEnforced": False, "error": str(e)}
