import json
import ast


def transform(input):
    """
    Evaluates isDataClassified for Vertica

    Checks: Whether database tables are cataloged in Vertica
    Pass Condition: At least 1 table exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isDataClassified": boolean, "totalSources": int}
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
        sources = data.get("results", data.get("data", data.get("sources",
            data.get("datastores", data.get("assets", data.get("catalogs",
            data.get("resources", [])))))))

        if not isinstance(sources, list):
            sources = [sources] if sources else []

        total = len(sources)
        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isDataClassified": result,
            "totalSources": total
        }

    except Exception as e:
        return {"isDataClassified": False, "error": str(e)}
