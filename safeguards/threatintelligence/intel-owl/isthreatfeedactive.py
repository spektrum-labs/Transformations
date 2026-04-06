import json
import ast


def transform(input):
    """
    Evaluates isThreatFeedActive for Intel Owl.

    Checks: Analysis jobs are accessible from the Intel Owl instance.
    API Source: GET {baseURL}/api/jobs
    Pass Condition: Response contains a non-empty list of analysis jobs or the endpoint is accessible.

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isThreatFeedActive": boolean}
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

        # Check for jobs data
        jobs = data if isinstance(data, list) else data.get("results", data.get("jobs", data.get("items", [])))
        if isinstance(jobs, list) and len(jobs) > 0:
            result = True
        elif isinstance(data, dict) and "count" in data:
            result = True
        else:
            result = False

        return {"isThreatFeedActive": result}

    except Exception as e:
        return {"isThreatFeedActive": False, "error": str(e)}
