import json
import ast


def transform(input):
    """
    Evaluates isTicketingEnabled for Atlassian User Provisioning (SCIM)

    Checks: Whether SCIM users are retrievable from the provisioning directory
    API Source: https://api.atlassian.com/scim/directory/{directoryId}/Users
    Pass Condition: The API returns a SCIM user list response

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isTicketingEnabled": boolean, "userCount": int}
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
        total_results = data.get("totalResults", 0)
        resources = data.get("Resources", data.get("resources", []))

        if isinstance(resources, list):
            result = True
            user_count = len(resources) if resources else total_results
        else:
            result = total_results > 0
            user_count = total_results
        # -- END EVALUATION LOGIC --

        return {
            "isTicketingEnabled": result,
            "userCount": user_count
        }

    except Exception as e:
        return {"isTicketingEnabled": False, "error": str(e)}
