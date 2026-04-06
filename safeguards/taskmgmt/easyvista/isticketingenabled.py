import json
import ast


def transform(input):
    """
    Evaluates isTicketingEnabled for EasyVista (ITSM)

    Checks: Whether tickets/requests are retrievable from EasyVista
    API Source: {baseURL}/api/v1/{accountId}/requests
    Pass Condition: API returns a list of requests without error

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isTicketingEnabled": boolean, "ticketCount": int}
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
        records = data.get("records", data.get("RECORDS", data.get("results", [])))

        if not isinstance(records, list):
            return {
                "isTicketingEnabled": False,
                "ticketCount": 0,
                "error": "Unexpected response format"
            }

        ticket_count = len(records)
        result = ticket_count >= 0 and not data.get("error", None)
        # -- END EVALUATION LOGIC --

        return {
            "isTicketingEnabled": result,
            "ticketCount": ticket_count
        }

    except Exception as e:
        return {"isTicketingEnabled": False, "error": str(e)}
