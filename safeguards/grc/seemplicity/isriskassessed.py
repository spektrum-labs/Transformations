import json
import ast


def transform(input):
    """
    Evaluates isRiskAssessed for Seemplicity

    Checks: Whether security findings are tracked with severity ratings
    API Source: {baseURL}/api/v1/findings
    Pass Condition: At least 1 finding exists with a severity or risk rating

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isRiskAssessed": boolean, "assessedFindings": int, "totalFindings": int}
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
        findings = data.get("results", data.get("data", data.get("items", data.get("findings", []))))

        if not isinstance(findings, list):
            return {
                "isRiskAssessed": False,
                "assessedFindings": 0,
                "totalFindings": 0,
                "error": "Unexpected findings response format"
            }

        total = len(findings)
        assessed = [
            f for f in findings
            if f.get("severity") or f.get("score") or f.get("risk_rating") or f.get("priority")
        ]
        result = len(assessed) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isRiskAssessed": result,
            "assessedFindings": len(assessed),
            "totalFindings": total
        }

    except Exception as e:
        return {"isRiskAssessed": False, "error": str(e)}
