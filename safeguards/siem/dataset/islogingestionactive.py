import json
import ast


def transform(input):
    """
    Evaluates isLogIngestionActive for SentinelOne DataSet

    Checks: Whether log sources are actively sending data via facet query
    API Source: /api/facetQuery (field=source)
    Pass Condition: At least one log source appears in the facet results

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isLogIngestionActive": boolean, "sourceCount": int}
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
        values = data.get("values", data.get("results", data.get("data", [])))
        if not isinstance(values, list):
            values = []

        count = len(values)
        result = count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isLogIngestionActive": result,
            "sourceCount": count
        }

    except Exception as e:
        return {"isLogIngestionActive": False, "error": str(e)}
