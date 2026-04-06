import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Joe Sandbox.

    Checks: Submission notifications are configured and submissions exist.
    API Source: GET https://jbxcloud.joesecurity.org/api/v2/submission/list
    Pass Condition: Response contains submissions with notification or callback data.

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

        # Check for submission data with notifications
        submissions = data if isinstance(data, list) else data.get("data", data.get("submissions", data.get("results", [])))
        if isinstance(submissions, list) and len(submissions) > 0:
            result = True
        elif isinstance(data, dict) and len(data) > 0 and "error" not in data:
            result = True
        else:
            result = False

        return {"isAlertingConfigured": result}

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
