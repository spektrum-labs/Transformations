import json
import ast


def transform(input):
    """
    Evaluates isContinuousMonitoringEnabled for Living Security

    Checks: Whether continuous human risk monitoring is active
    API Source: {baseURL}/api/v1/risk-scores
    Pass Condition: Risk scores are being calculated indicating active monitoring

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isContinuousMonitoringEnabled": boolean, "monitoringStatus": str}
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
        monitoring_status = "unknown"

        scores = data.get("riskScores", data.get("scores", data.get("data", data.get("results", []))))

        if isinstance(scores, list) and len(scores) > 0:
            result = True
            monitoring_status = "active"
        elif isinstance(scores, dict) and scores:
            result = bool(scores.get("overallScore") is not None or scores.get("riskScore") is not None)
            monitoring_status = "active" if result else "inactive"
        else:
            status = data.get("status", data.get("state", ""))
            if isinstance(status, str):
                monitoring_status = status.lower()
            active_states = {"active", "enabled", "running", "healthy"}
            result = monitoring_status in active_states
        # -- END EVALUATION LOGIC --

        return {
            "isContinuousMonitoringEnabled": result,
            "monitoringStatus": monitoring_status
        }

    except Exception as e:
        return {"isContinuousMonitoringEnabled": False, "error": str(e)}
