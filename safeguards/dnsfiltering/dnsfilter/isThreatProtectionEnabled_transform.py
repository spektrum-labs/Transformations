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
    Verifies core threat categories (malware, phishing, botnet) are blocked

    Parameters:
        input (dict): Policies data from GET /policies

    Returns:
        dict: {"isThreatProtectionEnabled": boolean, "blockedCategories": list}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # Required threat categories (case-insensitive)
        required_categories = {"malware", "phishing", "botnet"}

        policies = data if isinstance(data, list) else data.get("policies", [])

        if not policies:
            return {"isThreatProtectionEnabled": False, "error": "No policies found"}

        # Check if any policy has all required threat categories blocked
        for policy in policies:
            blacklisted = policy.get("blacklisted_categories", [])
            blocked_names = set()

            for cat in blacklisted:
                if isinstance(cat, dict):
                    name = cat.get("name", "").lower()
                elif isinstance(cat, str):
                    name = cat.lower()
                else:
                    continue
                blocked_names.add(name)

            # Check if all required categories are blocked
            if required_categories.issubset(blocked_names):
                return {
                    "isThreatProtectionEnabled": True,
                    "blockedCategories": list(blocked_names)
                }

        return {"isThreatProtectionEnabled": False}

    except Exception as e:
        return {"isThreatProtectionEnabled": False, "error": str(e)}
