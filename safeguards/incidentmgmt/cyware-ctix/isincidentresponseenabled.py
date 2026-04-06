import json
import ast


def transform(input):
    """
    Evaluates isIncidentResponseEnabled for Cyware CTIX

    Checks: Whether incidents are retrievable from the CTIX incidents API
    API Source: /api/v3/incidents/
    Pass Condition: At least one incident exists or the API responds successfully

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
        incidents = data.get("incidents", data.get("data", data.get("results", [])))
        if not isinstance(incidents, list):
            incidents = []

        total = len(incidents)
        result = isinstance(data, dict) and data.get("error") is None
        # -- END EVALUATION LOGIC --

        return {
            "isIncidentResponseEnabled": result,
            "totalIncidents": total
        }

    except Exception as e:
        return {"isIncidentResponseEnabled": False, "error": str(e)}
