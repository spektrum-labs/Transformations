import json
import ast


def transform(input):
    """
    Evaluates isThreatAnalysisEnabled for Shodan.

    Checks: Whether host detail reports are accessible via the host endpoint
    API Source: GET https://api.shodan.io/shodan/host/{ip}
    Pass Condition: Response contains valid host data with ports and services

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
        ports = data.get("ports", data.get("data", []))
        has_metadata = isinstance(data, dict) and (isinstance(ports, list) and len(ports) > 0 or len(data) > 2)

        result = has_metadata and not has_error
        # -- END EVALUATION LOGIC --

        return {
            "isThreatAnalysisEnabled": result,
            "hasMetadata": has_metadata
        }

    except Exception as e:
        return {"isThreatAnalysisEnabled": False, "error": str(e)}
