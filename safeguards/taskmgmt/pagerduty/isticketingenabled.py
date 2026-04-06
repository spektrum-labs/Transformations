import json
import ast


def transform(input):
    """
    Evaluates isTicketingEnabled for PagerDuty

    Checks: Whether incidents can be retrieved from PagerDuty
    API Source: https://api.pagerduty.com/incidents
    Pass Condition: API returns a successful response with an incidents array

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isTicketingEnabled": boolean, "incidentCount": int}
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
        incidents = data.get("incidents", data.get("data", []))

        if not isinstance(incidents, list):
            return {
                "isTicketingEnabled": False,
                "incidentCount": 0,
                "error": "Unexpected incidents response format"
            }

        count = len(incidents)
        result = True  # Successful API response confirms ticketing is enabled
        # -- END EVALUATION LOGIC --

        return {
            "isTicketingEnabled": result,
            "incidentCount": count
        }

    except Exception as e:
        return {"isTicketingEnabled": False, "error": str(e)}
