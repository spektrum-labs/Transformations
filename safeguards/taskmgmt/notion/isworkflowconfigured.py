import json
import ast


def transform(input):
    """
    Evaluates isWorkflowConfigured for Notion (All-in-One Workspace)

    Checks: Whether pages are accessible and shared with the integration
    API Source: https://api.notion.com/v1/search (pages filter)
    Pass Condition: At least 1 page is returned

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isWorkflowConfigured": boolean, "pageCount": int}
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
        results = data.get("results", [])

        if not isinstance(results, list):
            return {
                "isWorkflowConfigured": False,
                "pageCount": 0,
                "error": "Unexpected response format"
            }

        pages = [r for r in results if r.get("object") == "page"]
        page_count = len(pages)
        result = page_count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isWorkflowConfigured": result,
            "pageCount": page_count
        }

    except Exception as e:
        return {"isWorkflowConfigured": False, "error": str(e)}
