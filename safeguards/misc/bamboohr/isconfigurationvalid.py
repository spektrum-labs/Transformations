import json
import ast


def transform(input):
    """
    Evaluates isConfigurationValid for BambooHR

    Checks: Whether field metadata is retrievable from BambooHR
    API Source: GET https://api.bamboohr.com/api/gateway.php/{subdomain}/v1/meta/fields
    Pass Condition: Field metadata is returned successfully

    Parameters:
        input (dict): JSON data containing API response from meta fields endpoint

    Returns:
        dict: {"isConfigurationValid": boolean, "fieldCount": int}
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
        error = data.get("error", data.get("errors", None))
        if error:
            return {"isConfigurationValid": False, "fieldCount": 0}

        fields = data.get("fields", data.get("data", []))
        if isinstance(fields, list):
            result = True
            field_count = len(fields)
        elif isinstance(data, list):
            result = True
            field_count = len(data)
        else:
            result = True
            field_count = 0
        # -- END EVALUATION LOGIC --

        return {
            "isConfigurationValid": result,
            "fieldCount": field_count
        }

    except Exception as e:
        return {"isConfigurationValid": False, "error": str(e)}
