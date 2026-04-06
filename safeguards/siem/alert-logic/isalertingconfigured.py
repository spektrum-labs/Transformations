import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Alert Logic

    Checks: Whether incidents and alerting are configured and active
    API Source: /iris/v3/{accountId}/incidents
    Pass Condition: Incidents endpoint returns data, indicating the detection engine is active

    Parameters:
        input (dict): JSON data containing API response

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
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # -- EVALUATION LOGIC --
        incidents = data.get("incidents", data.get("data", data.get("items", [])))
        if isinstance(incidents, dict):
            incidents = list(incidents.values()) if incidents else []
        if not isinstance(incidents, list):
            incidents = []

        count = len(incidents)
        result = isinstance(data, dict) and not data.get("error")
        # -- END EVALUATION LOGIC --

        return {
            "isAlertingConfigured": result,
            "incidentCount": count
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
