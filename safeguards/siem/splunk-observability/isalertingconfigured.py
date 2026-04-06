import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Splunk Observability Cloud

    Checks: Whether detectors (alert rules) are configured in Splunk
            Observability by checking the detector endpoint for active detectors.

    API Source: GET {baseURL}/v2/detector?limit=50
    Pass Condition: At least one detector exists, confirming that alerting
                    is configured for infrastructure and application monitoring.

    Parameters:
        input (dict): JSON data containing API response from the detector endpoint

    Returns:
        dict: {"isAlertingConfigured": boolean, "detectorCount": int}
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

        # Standard response unwrapping chain
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # Splunk Observability returns detectors as results array
        detectors = data if isinstance(data, list) else data.get("results", data.get("data", []))
        if not isinstance(detectors, list):
            # Check for count field
            count = data.get("count", data.get("total", 0))
            if isinstance(count, (int, float)) and count > 0:
                return {
                    "isAlertingConfigured": True,
                    "detectorCount": int(count)
                }
            detectors = []

        detector_count = len(detectors)
        result = detector_count > 0

        return {
            "isAlertingConfigured": result,
            "detectorCount": detector_count
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
