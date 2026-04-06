import json
import ast


def transform(input):
    """
    Evaluates isThreatAnalysisEnabled for AlienVault OTX.

    Checks: Whether subscribed pulses (threat reports) are available
    API Source: GET https://otx.alienvault.com/api/v1/pulses/subscribed
    Pass Condition: At least one subscribed pulse exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isThreatAnalysisEnabled": boolean, "pulseCount": int}
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
        pulses = data.get("results", data.get("data", []))
        if not isinstance(pulses, list):
            pulses = []

        count = len(pulses)
        result = count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isThreatAnalysisEnabled": result,
            "pulseCount": count
        }

    except Exception as e:
        return {"isThreatAnalysisEnabled": False, "error": str(e)}
