import json
import ast


def transform(input):
    """
    Evaluates isRiskAssessed for Anvilogic

    Checks: Whether threat scenarios are defined and evaluated
    API Source: {baseURL}/api/v1/threat-scenarios
    Pass Condition: At least 1 threat scenario exists with severity or scoring

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isRiskAssessed": boolean, "assessedThreats": int, "totalThreats": int}
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
        threats = data.get("results", data.get("data", data.get("items", data.get("threat_scenarios", []))))

        if not isinstance(threats, list):
            return {
                "isRiskAssessed": False,
                "assessedThreats": 0,
                "totalThreats": 0,
                "error": "Unexpected threat scenarios response format"
            }

        total = len(threats)
        assessed = [
            t for t in threats
            if t.get("severity") or t.get("score") or t.get("risk_level") or t.get("priority")
        ]
        result = len(assessed) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isRiskAssessed": result,
            "assessedThreats": len(assessed),
            "totalThreats": total
        }

    except Exception as e:
        return {"isRiskAssessed": False, "error": str(e)}
