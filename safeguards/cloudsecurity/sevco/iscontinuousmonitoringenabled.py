import json
import ast


def transform(input):
    """
    Evaluates isContinuousMonitoringEnabled for Sevco Security

    Checks: Whether data sources are actively reporting
    API Source: {baseURL}/v1/sources/status
    Pass Condition: At least one data source is actively reporting

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isContinuousMonitoringEnabled": boolean, "reportingSources": int}
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
        sources = data.get("data", data.get("results", data.get("items", data.get("sources", []))))

        if isinstance(sources, list):
            reporting = [
                s for s in sources
                if s.get("status", "").lower() in ("active", "healthy", "connected", "reporting")
            ]
            count = len(reporting)
        else:
            status = data.get("status", "")
            if isinstance(status, str):
                status = status.lower()
            count = 1 if status in ("active", "healthy", "ok", "operational") else 0

        result = count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isContinuousMonitoringEnabled": result,
            "reportingSources": count
        }

    except Exception as e:
        return {"isContinuousMonitoringEnabled": False, "error": str(e)}
