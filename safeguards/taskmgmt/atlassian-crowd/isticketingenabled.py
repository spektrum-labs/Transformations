import json
import ast


def transform(input):
    """
    Evaluates isTicketingEnabled for Atlassian Crowd

    Checks: Whether users are searchable in the Crowd directory
    API Source: {baseURL}/rest/usermanagement/latest/search?entity-type=user
    Pass Condition: The API returns a user search result

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
        users = data.get("users", data.get("data", data.get("results", [])))

        if isinstance(users, list):
            user_count = len(users)
            result = True
        else:
            user_count = 0
            result = bool(data)
        # -- END EVALUATION LOGIC --

        return {
            "isTicketingEnabled": result,
            "userCount": user_count
        }

    except Exception as e:
        return {"isTicketingEnabled": False, "error": str(e)}
