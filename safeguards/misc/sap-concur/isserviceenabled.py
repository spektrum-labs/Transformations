import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for SAP Concur

    Checks: Whether expense reports are retrievable from SAP Concur
    API Source: https://{dataCenterUrl}/api/v3.0/expense/reports
    Pass Condition: The API returns an expense reports response

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isServiceEnabled": boolean, "reportCount": int}
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
        items = data.get("Items", data.get("items", []))
        if isinstance(items, list):
            result = True
            report_count = len(items)
        else:
            result = bool(data) and "error" not in data
            report_count = 0
        # -- END EVALUATION LOGIC --

        return {
            "isServiceEnabled": result,
            "reportCount": report_count
        }

    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
