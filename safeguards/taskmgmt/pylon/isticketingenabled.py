import json
import ast


def transform(input):
    """
    Evaluates isTicketingEnabled for Pylon

    Checks: Whether issues can be retrieved from Pylon
    API Source: https://api.usepylon.com/issues
    Pass Condition: API returns a successful response with issues data

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isTicketingEnabled": boolean, "issueCount": int}
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
        issues = data.get("data", data.get("issues", data.get("results", [])))

        if not isinstance(issues, list):
            return {
                "isTicketingEnabled": False,
                "issueCount": 0,
                "error": "Unexpected issues response format"
            }

        count = len(issues)
        result = True  # Successful API response confirms ticketing is enabled
        # -- END EVALUATION LOGIC --

        return {
            "isTicketingEnabled": result,
            "issueCount": count
        }

    except Exception as e:
        return {"isTicketingEnabled": False, "error": str(e)}
