import json
import ast


def transform(input):
    """
    Evaluates isLogCollectionActive for New Relic

    Checks: Whether at least one application is reporting data
    API Source: https://api.newrelic.com/v2/applications.json
    Pass Condition: At least one application exists and is reporting

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isLogCollectionActive": boolean, "activeSources": int, "totalSources": int}
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
        applications = data.get("applications", data.get("data", data.get("items", [])))

        if not isinstance(applications, list):
            applications = [applications] if applications else []

        total = len(applications)
        active = [a for a in applications if a.get("reporting", False)] if applications else []

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isLogCollectionActive": result,
            "activeSources": len(active),
            "totalSources": total
        }

    except Exception as e:
        return {"isLogCollectionActive": False, "error": str(e)}
