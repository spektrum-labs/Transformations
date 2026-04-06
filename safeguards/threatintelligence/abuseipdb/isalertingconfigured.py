import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for AbuseIPDB.

    Checks: Whether the check-block endpoint returns network monitoring data
    API Source: GET https://api.abuseipdb.com/api/v2/check-block
    Pass Condition: Response contains valid block-check data indicating monitoring is active

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAlertingConfigured": boolean, "hasBlockData": boolean}
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
        has_error = data.get("errors") is not None or data.get("error") is not None
        report_data = data.get("data", {})

        if isinstance(report_data, dict):
            has_data = len(report_data) > 0
        elif isinstance(report_data, list):
            has_data = len(report_data) > 0
        else:
            has_data = False

        result = has_data and not has_error
        # -- END EVALUATION LOGIC --

        return {
            "isAlertingConfigured": result,
            "hasBlockData": has_data
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
