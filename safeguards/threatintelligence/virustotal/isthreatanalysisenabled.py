import json
import ast


def transform(input):
    """
    Evaluates isThreatAnalysisEnabled for VirusTotal.

    Checks: Whether file analysis reports are accessible
    API Source: GET https://www.virustotal.com/api/v3/files/{id}
    Pass Condition: Response contains valid file analysis data with scan results

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isThreatAnalysisEnabled": boolean, "hasMetadata": boolean}
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
        has_error = data.get("error") is not None
        file_data = data.get("data", data)
        attributes = file_data.get("attributes", {}) if isinstance(file_data, dict) else {}
        has_metadata = isinstance(attributes, dict) and len(attributes) > 0

        if not has_metadata:
            has_metadata = isinstance(file_data, dict) and len(file_data) > 1

        result = has_metadata and not has_error
        # -- END EVALUATION LOGIC --

        return {
            "isThreatAnalysisEnabled": result,
            "hasMetadata": has_metadata
        }

    except Exception as e:
        return {"isThreatAnalysisEnabled": False, "error": str(e)}
