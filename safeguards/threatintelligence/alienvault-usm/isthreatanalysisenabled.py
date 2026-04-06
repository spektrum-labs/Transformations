import json
import ast


def transform(input):
    """
    Evaluates isThreatAnalysisEnabled for AlienVault USM Anywhere.

    Checks: Whether reports are available from USM Anywhere
    API Source: GET https://{subdomain}.alienvault.cloud/api/2.0/reports
    Pass Condition: At least one report exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isThreatAnalysisEnabled": boolean, "reportCount": int}
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
        reports = data.get("_embedded", {}).get("reports", data.get("data", data.get("results", [])))
        if not isinstance(reports, list):
            reports = []

        count = len(reports)
        result = count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isThreatAnalysisEnabled": result,
            "reportCount": count
        }

    except Exception as e:
        return {"isThreatAnalysisEnabled": False, "error": str(e)}
