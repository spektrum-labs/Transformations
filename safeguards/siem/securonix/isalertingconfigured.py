import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Securonix SIEM

    Checks: Whether incidents/alerts are being generated in Securonix by
            checking the incident list endpoint for existing alert records.

    API Source: GET {baseURL}/ws/incident/get?type=list&max=50
    Pass Condition: At least one incident record exists, confirming that
                    alerting rules and threat detection are operational.

    Parameters:
        input (dict): JSON data containing API response from the incident endpoint

    Returns:
        dict: {"isAlertingConfigured": boolean, "incidentCount": int}
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

        # Standard response unwrapping chain
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # Securonix incident endpoint returns incidents under data or result
        incidents = data if isinstance(data, list) else data.get("data", data.get("incidentItems", data.get("result", [])))
        if not isinstance(incidents, list):
            # Check for totalIncidents count field
            total = data.get("totalIncidents", data.get("total", 0))
            if isinstance(total, (int, float)) and total > 0:
                return {
                    "isAlertingConfigured": True,
                    "incidentCount": int(total)
                }
            incidents = []

        incident_count = len(incidents)
        result = incident_count > 0

        return {
            "isAlertingConfigured": result,
            "incidentCount": incident_count
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
