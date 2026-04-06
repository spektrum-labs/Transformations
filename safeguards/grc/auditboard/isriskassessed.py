import json
import ast


def transform(input):
    """
    Evaluates isRiskAssessed for AuditBoard

    Checks: Whether risk entries exist with scoring and ownership
    API Source: {baseURL}/v1/risks
    Pass Condition: At least 1 risk exists with a score or rating assigned

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
        risks = data.get("results", data.get("data", data.get("items", data.get("risks", []))))

        if not isinstance(risks, list):
            return {
                "isRiskAssessed": False,
                "assessedRisks": 0,
                "totalRisks": 0,
                "error": "Unexpected risks response format"
            }

        total = len(risks)
        assessed = [
            r for r in risks
            if r.get("severity") or r.get("score") or r.get("risk_rating") or r.get("impact")
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
