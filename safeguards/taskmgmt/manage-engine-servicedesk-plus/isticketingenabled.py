import json
import ast


def transform(input):
    """
    Evaluates isTicketingEnabled for ManageEngine ServiceDesk Plus (On-Premise)

    Checks: Whether requests are retrievable from ServiceDesk Plus
    API Source: {baseURL}/api/v3/requests
    Pass Condition: API returns a list of requests without error

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isTicketingEnabled": boolean, "requestCount": int}
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
        requests = data.get("requests", data.get("results", []))

        if not isinstance(requests, list):
            return {
                "isTicketingEnabled": False,
                "requestCount": 0,
                "error": "Unexpected response format"
            }

        request_count = len(requests)
        result = request_count >= 0 and not data.get("error", None)
        # -- END EVALUATION LOGIC --

        return {
            "isTicketingEnabled": result,
            "requestCount": request_count
        }

    except Exception as e:
        return {"isTicketingEnabled": False, "error": str(e)}
