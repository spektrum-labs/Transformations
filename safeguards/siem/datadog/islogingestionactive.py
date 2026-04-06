import json
import ast


def transform(input):
    """
    Evaluates isLogIngestionActive for Datadog

    Checks: Whether log pipelines are configured and processing data
    API Source: /api/v1/logs/config/pipelines
    Pass Condition: At least one log pipeline exists and is enabled

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isLogIngestionActive": boolean, "activePipelines": int, "totalPipelines": int}
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
        pipelines = data if isinstance(data, list) else data.get("pipelines", data.get("data", []))
        if not isinstance(pipelines, list):
            return {
                "isLogIngestionActive": False,
                "activePipelines": 0,
                "totalPipelines": 0,
                "error": "Unexpected pipelines response format"
            }

        total = len(pipelines)
        active = [
            p for p in pipelines
            if p.get("is_enabled", p.get("enabled", False)) is True
        ]

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isLogIngestionActive": result,
            "activePipelines": len(active),
            "totalPipelines": total
        }

    except Exception as e:
        return {"isLogIngestionActive": False, "error": str(e)}
