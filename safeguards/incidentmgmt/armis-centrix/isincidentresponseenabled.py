import json
import ast


def transform(input):
    """
    Evaluates isIncidentResponseEnabled for Armis Centrix

    Checks: Whether policy violation alerts are retrievable from Armis Centrix
    API Source: /api/v1/alerts/?type=POLICY_VIOLATION
    Pass Condition: At least one policy violation alert exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isIncidentResponseEnabled": boolean, "totalIncidents": int}
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
        incidents = data.get("data", data.get("results", data.get("alerts", [])))
        if not isinstance(incidents, list):
            incidents = []

        total = len(incidents)
        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isIncidentResponseEnabled": result,
            "totalIncidents": total
        }

    except Exception as e:
        return {"isIncidentResponseEnabled": False, "error": str(e)}
