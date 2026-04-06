import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for PagerDuty

    Checks: Whether the PagerDuty API is responding successfully
    API Source: https://api.pagerduty.com/abilities
    Pass Condition: API returns a successful response with abilities array

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isIntegrationHealthy": boolean, "abilities": list}
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
        abilities = data.get("abilities", [])

        if not isinstance(abilities, list):
            abilities = []

        result = len(abilities) >= 1 or bool(data)
        # -- END EVALUATION LOGIC --

        return {
            "isIntegrationHealthy": result,
            "abilities": abilities if isinstance(abilities, list) else []
        }

    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
