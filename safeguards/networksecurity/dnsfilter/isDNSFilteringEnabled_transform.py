import json
import ast


def _parse_input(input):
    if isinstance(input, str):
        try:
            parsed = ast.literal_eval(input)
            if isinstance(parsed, dict):
                return parsed
        except:
            pass
        try:
            input = input.replace("'", '"')
            return json.loads(input)
        except:
            raise ValueError("Input string is neither valid Python literal nor JSON")
    if isinstance(input, bytes):
        return json.loads(input.decode("utf-8"))
    if isinstance(input, dict):
        return input
    raise ValueError("Input must be JSON string, bytes, or dict")


def transform(input):
    """
    Confirms at least one active filtering policy exists

    Parameters:
        input (dict): Policies data from GET /policies

    Returns:
        dict: {"isDNSFilteringEnabled": boolean, "policyCount": int}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        policies = data if isinstance(data, list) else data.get("policies", [])

        # DNS filtering is enabled if at least one policy exists
        policy_count = len(policies)
        is_enabled = policy_count > 0

        return {
            "isDNSFilteringEnabled": is_enabled,
            "policyCount": policy_count
        }

    except Exception as e:
        return {"isDNSFilteringEnabled": False, "error": str(e)}
