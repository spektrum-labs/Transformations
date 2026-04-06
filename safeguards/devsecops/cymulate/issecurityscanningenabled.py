import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for Cymulate (Breach & Attack Simulation)

    Checks: Whether attack simulation assessments are actively running
    API Source: GET https://api.cymulate.com/v1/assessments/history
    Pass Condition: At least one assessment exists indicating active security testing

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean}
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
        result = False

        # Check for assessment records indicating active breach simulation
        assessments = data.get("data", data.get("assessments", data.get("results", [])))
        if isinstance(assessments, list) and len(assessments) > 0:
            result = True
        elif isinstance(assessments, dict) and assessments.get("id"):
            result = True
        elif data.get("total", data.get("count", 0)) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isSecurityScanningEnabled": result}
    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
