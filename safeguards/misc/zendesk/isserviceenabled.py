import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for Zendesk.

    Checks: Whether the Zendesk support service is active by confirming tickets
            are retrievable via the Support API.
    API Source: GET https://{subdomain}.zendesk.com/api/v2/tickets.json
    Pass Condition: API returns ticket data or an empty list without errors

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isServiceEnabled": boolean}
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
        tickets = data.get("tickets", data.get("data", data.get("results", [])))
        error = data.get("error", data.get("errors", None))

        if error:
            result = False
        elif isinstance(tickets, list):
            result = True
        elif isinstance(data, dict) and len(data) > 0 and not error:
            result = True
        else:
            result = False
        # -- END EVALUATION LOGIC --

        return {"isServiceEnabled": result}

    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
