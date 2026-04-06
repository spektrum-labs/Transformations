import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for Tableau

    Checks: Whether workbooks are retrievable from Tableau Server
    API Source: {serverUrl}/api/{apiVersion}/sites/{siteId}/workbooks
    Pass Condition: The API returns a workbooks response

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isServiceEnabled": boolean, "workbookCount": int}
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
        workbooks_container = data.get("workbooks", {})
        workbooks = workbooks_container.get("workbook", []) if isinstance(workbooks_container, dict) else []
        if isinstance(workbooks, list):
            result = True
            workbook_count = len(workbooks)
        else:
            result = bool(data) and "error" not in data
            workbook_count = 0
        # -- END EVALUATION LOGIC --

        return {
            "isServiceEnabled": result,
            "workbookCount": workbook_count
        }

    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
