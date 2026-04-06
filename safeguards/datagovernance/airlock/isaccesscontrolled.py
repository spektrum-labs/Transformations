import json
import ast


def transform(input):
    """
    Evaluates isAccessControlled for Airlock WAF

    Checks: Whether at least one mapping/policy rule is configured for access control
    API Source: https://{host}:4443/airlock/rest/configuration/mappings
    Pass Condition: At least one mapping exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAccessControlled": boolean, "activePolicies": int, "totalPolicies": int}
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
        mappings = data.get("data", data.get("mappings", data.get("items", [])))

        if not isinstance(mappings, list):
            mappings = [mappings] if mappings else []

        total = len(mappings)
        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isAccessControlled": result,
            "activePolicies": total,
            "totalPolicies": total
        }

    except Exception as e:
        return {"isAccessControlled": False, "error": str(e)}
