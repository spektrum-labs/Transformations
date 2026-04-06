import json
import ast


def transform(input):
    """
    Evaluates isRiskAssessed for GYTPOL (Remedio)

    Checks: Whether device misconfigurations are identified and scored
    API Source: {baseURL}/misconfigurations
    Pass Condition: At least 1 misconfiguration exists with a severity or risk level

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isRiskAssessed": boolean, "assessedRisks": int, "totalRisks": int}
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
        misconfigs = data.get("results", data.get("data", data.get("items", data.get("misconfigurations", []))))

        if not isinstance(misconfigs, list):
            return {
                "isRiskAssessed": False,
                "assessedRisks": 0,
                "totalRisks": 0,
                "error": "Unexpected misconfigurations response format"
            }

        total = len(misconfigs)
        assessed = [
            m for m in misconfigs
            if m.get("severity") or m.get("risk_level") or m.get("score") or m.get("priority")
        ]
        result = len(assessed) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isRiskAssessed": result,
            "assessedRisks": len(assessed),
            "totalRisks": total
        }

    except Exception as e:
        return {"isRiskAssessed": False, "error": str(e)}
