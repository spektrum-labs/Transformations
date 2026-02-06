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
    Confirms phishing category is blocked in filtering policies

    Parameters:
        input (dict): Policies data from GET /policies

    Returns:
        dict: {"isPhishingProtectionEnabled": boolean}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        policies = data if isinstance(data, list) else data.get("policies", [])

        if not policies:
            return {"isPhishingProtectionEnabled": False, "error": "No policies found"}

        for policy in policies:
            blacklisted = policy.get("blacklisted_categories", [])

            for cat in blacklisted:
                name = ""
                if isinstance(cat, dict):
                    name = cat.get("name", "").lower()
                elif isinstance(cat, str):
                    name = cat.lower()

                if "phishing" in name:
                    return {"isPhishingProtectionEnabled": True}

        return {"isPhishingProtectionEnabled": False}

    except Exception as e:
        return {"isPhishingProtectionEnabled": False, "error": str(e)}
