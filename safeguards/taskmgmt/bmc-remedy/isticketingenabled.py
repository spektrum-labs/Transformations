import json
import ast


def transform(input):
    """
    Evaluates isTicketingEnabled for BMC Remedy

    Checks: Whether incidents are retrievable from the BMC Remedy Help Desk
    API Source: {baseURL}/api/arsys/v1/entry/HPD:Help Desk
    Pass Condition: The API returns an entries array (even if empty)

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
        entries = data.get("entries", data.get("data", data.get("results", [])))

        if isinstance(entries, list):
            result = True
            incident_count = len(entries)
        else:
            result = bool(data)
            incident_count = 0
        # -- END EVALUATION LOGIC --

        return {
            "isTicketingEnabled": result,
            "incidentCount": incident_count
        }

    except Exception as e:
        return {"isTicketingEnabled": False, "error": str(e)}
