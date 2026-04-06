import json
import ast


def transform(input):
    """
    Evaluates isThreatAnalysisEnabled for Spur.

    Checks: Whether IP context reports contain enrichment attributes
    API Source: GET https://api.spur.us/v2/context/{ip}
    Pass Condition: Response contains valid enrichment data with geography, ASN, or proxy attribution

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
        has_geo = data.get("location", data.get("geoLite", None)) is not None
        has_as = data.get("as", data.get("organization", None)) is not None
        has_metadata = isinstance(data, dict) and (has_geo or has_as) and len(data) > 1

        result = has_metadata and not has_error
        # -- END EVALUATION LOGIC --

        return {
            "isThreatAnalysisEnabled": result,
            "hasMetadata": has_metadata
        }

    except Exception as e:
        return {"isThreatAnalysisEnabled": False, "error": str(e)}
