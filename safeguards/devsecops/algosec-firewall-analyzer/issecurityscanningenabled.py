import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for AlgoSec Firewall Analyzer

    Checks: Whether risk analysis reports are available from the firewall analyzer
    API Source: {baseURL}/afa/api/v1/risks
    Pass Condition: At least one risk analysis result exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean, "activeScans": int, "totalScans": int}
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
        risks = data.get("data", data.get("risks", data.get("results", data.get("items", []))))

        if not isinstance(risks, list):
            return {
                "isSecurityScanningEnabled": False,
                "activeScans": 0,
                "totalScans": 0,
                "error": "Unexpected response format"
            }

        total = len(risks)
        active = []
        for risk in risks:
            severity = risk.get("severity", risk.get("risk_level", risk.get("status", "")))
            if severity:
                active.append(risk)

        result = len(active) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityScanningEnabled": result,
            "activeScans": len(active),
            "totalScans": total
        }

    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
