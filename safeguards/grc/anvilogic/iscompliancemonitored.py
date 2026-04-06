import json
import ast


def transform(input):
    """
    Evaluates isComplianceMonitored for Anvilogic

    Checks: Whether detection rules are deployed and actively monitoring
    API Source: {baseURL}/api/v1/detections
    Pass Condition: At least 1 detection rule exists with an active or enabled status

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isComplianceMonitored": boolean, "activeDetections": int, "totalDetections": int}
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
        detections = data.get("results", data.get("data", data.get("items", data.get("detections", []))))

        if not isinstance(detections, list):
            return {
                "isComplianceMonitored": False,
                "activeDetections": 0,
                "totalDetections": 0,
                "error": "Unexpected detections response format"
            }

        total = len(detections)
        active = [
            d for d in detections
            if str(d.get("status", "")).lower() in ("active", "enabled", "deployed")
        ]
        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isComplianceMonitored": result,
            "activeDetections": len(active),
            "totalDetections": total
        }

    except Exception as e:
        return {"isComplianceMonitored": False, "error": str(e)}
