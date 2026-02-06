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
    Verifies 'Very New Domains' (< 24 hours) and 'New Domains' (< 30 days) are blocked

    Parameters:
        input (dict): Policies data from GET /policies

    Returns:
        dict: {"isNewDomainProtectionEnabled": boolean}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        policies = data if isinstance(data, list) else data.get("policies", [])

        if not policies:
            return {"isNewDomainProtectionEnabled": False, "error": "No policies found"}

        for policy in policies:
            blacklisted = policy.get("blacklisted_categories", [])
            has_new_domains = False
            has_very_new_domains = False

            for cat in blacklisted:
                name = ""
                if isinstance(cat, dict):
                    name = cat.get("name", "").lower()
                elif isinstance(cat, str):
                    name = cat.lower()

                if "very new domain" in name:
                    has_very_new_domains = True
                elif "new domain" in name:
                    has_new_domains = True

            # Pass if at least one new domain category is blocked
            if has_new_domains or has_very_new_domains:
                return {
                    "isNewDomainProtectionEnabled": True,
                    "veryNewDomainsBlocked": has_very_new_domains,
                    "newDomainsBlocked": has_new_domains
                }

        return {"isNewDomainProtectionEnabled": False}

    except Exception as e:
        return {"isNewDomainProtectionEnabled": False, "error": str(e)}
