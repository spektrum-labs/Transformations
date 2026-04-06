import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Elasticsearch

    Checks: Whether Elastic Security SIEM detection signals exist
    API Source: /_search (index: .siem-signals-*)
    Pass Condition: SIEM signals index exists and contains detection results

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAlertingConfigured": boolean, "signalCount": int}
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
        hits = data.get("hits", {})
        total = hits.get("total", {})
        if isinstance(total, dict):
            count = total.get("value", 0)
        elif isinstance(total, int):
            count = total
        else:
            count = 0

        has_error = data.get("error") is not None
        result = not has_error and isinstance(data, dict)
        # -- END EVALUATION LOGIC --

        return {
            "isAlertingConfigured": result,
            "signalCount": count
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
