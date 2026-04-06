import json
import ast


def transform(input):
    """
    Evaluates isThreatAnalysisEnabled for AbuseIPDB.

    Checks: Whether the check endpoint returns threat analysis data for an IP
    API Source: GET https://api.abuseipdb.com/api/v2/check
    Pass Condition: Response contains valid analysis data with abuse confidence score

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isThreatAnalysisEnabled": boolean, "hasAnalysisData": boolean}
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
        check_data = data.get("data", {})
        if not isinstance(check_data, dict):
            check_data = {}

        has_score = "abuseConfidenceScore" in check_data
        has_reports = check_data.get("totalReports", 0) is not None

        result = has_score or has_reports
        # -- END EVALUATION LOGIC --

        return {
            "isThreatAnalysisEnabled": result,
            "hasAnalysisData": has_score
        }

    except Exception as e:
        return {"isThreatAnalysisEnabled": False, "error": str(e)}
