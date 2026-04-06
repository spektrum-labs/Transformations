import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for LimaCharlie.

    Checks: Output modules are configured for the organization.
    API Source: GET https://api.limacharlie.io/v1/output/{oid}
    Pass Condition: Response contains at least one configured output module.

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAlertingConfigured": boolean}
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

        # Check for output module configuration
        outputs = data if isinstance(data, list) else data.get("outputs", data.get("results", data.get("items", [])))
        if isinstance(outputs, list) and len(outputs) > 0:
            result = True
        elif isinstance(data, dict) and len(data) > 0 and "error" not in data:
            # Output modules may be returned as a dict of named outputs
            output_keys = [k for k in data.keys() if k not in ("response", "result", "apiResponse", "error")]
            result = len(output_keys) > 0
        else:
            result = False

        return {"isAlertingConfigured": result}

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
