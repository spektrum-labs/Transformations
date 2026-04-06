import json
import ast


def transform(input):
    """
    Evaluates isThreatAnalysisEnabled for PhishLabs Open Web Monitoring

    Checks: Whether PhishLabs Open Web Monitoring case reports are accessible
    API Source: GET https://caseapi.phishlabs.com/v1/data/cases
    Pass Condition: At least one case report is present in the response

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
        reports = data.get("data", data.get("results", data.get("cases", data.get("items", []))))

        if isinstance(reports, list):
            count = len(reports)
        elif isinstance(reports, dict):
            count = 1
        else:
            count = 0

        total = data.get("meta", {}).get("total", count)
        if isinstance(total, (int, float)) and total > count:
            count = int(total)

        result = count > 0
        # -- END EVALUATION LOGIC --

        return {
            "isThreatAnalysisEnabled": result,
            "reportCount": count
        }

    except Exception as e:
        return {"isThreatAnalysisEnabled": False, "error": str(e)}
