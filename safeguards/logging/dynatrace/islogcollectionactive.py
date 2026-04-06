import json
import ast


def transform(input):
    """
    Evaluates isLogCollectionActive for Dynatrace

    Checks: Whether at least one monitored host entity exists
    API Source: https://{env-id}.live.dynatrace.com/api/v2/entities?entitySelector=type(HOST)
    Pass Condition: At least one host entity is returned

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isLogCollectionActive": boolean, "activeSources": int, "totalSources": int}
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
        entities = data.get("entities", data.get("data", data.get("items", [])))

        if not isinstance(entities, list):
            entities = [entities] if entities else []

        total = data.get("totalCount", len(entities))
        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isLogCollectionActive": result,
            "activeSources": total,
            "totalSources": total
        }

    except Exception as e:
        return {"isLogCollectionActive": False, "error": str(e)}
