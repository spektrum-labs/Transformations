import json
import ast


def transform(input):
    """
    Evaluates isCompletionTracked for Traliant LMS

    Checks: Whether enrollment progress and completion tracking is active
    API Source: GET {baseURL}/api/v1/enrollments
    Pass Condition: At least one enrollment record exists with progress data

    Parameters:
        input (dict): JSON data containing API response from enrollments endpoint

    Returns:
        dict: {"isCompletionTracked": boolean, "enrollmentCount": int}
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
        enrollments = (
            data.get("enrollments") or
            data.get("results") or
            data.get("data") or
            data.get("items") or
            (data if isinstance(data, list) else [])
        )

        if not isinstance(enrollments, list):
            enrollments = []

        result = len(enrollments) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isCompletionTracked": result,
            "enrollmentCount": len(enrollments)
        }

    except Exception as e:
        return {"isCompletionTracked": False, "error": str(e)}
