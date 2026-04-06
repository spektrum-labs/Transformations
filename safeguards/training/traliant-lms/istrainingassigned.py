import json
import ast


def transform(input):
    """
    Evaluates isTrainingAssigned for Traliant LMS

    Checks: Whether at least one compliance training course is assigned
    API Source: GET {baseURL}/api/v1/courses
    Pass Condition: At least one course exists in the response

    Parameters:
        input (dict): JSON data containing API response from courses endpoint

    Returns:
        dict: {"isTrainingAssigned": boolean, "courseCount": int}
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
        courses = (
            data.get("courses") or
            data.get("results") or
            data.get("data") or
            data.get("items") or
            (data if isinstance(data, list) else [])
        )

        if not isinstance(courses, list):
            courses = []

        result = len(courses) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isTrainingAssigned": result,
            "courseCount": len(courses)
        }

    except Exception as e:
        return {"isTrainingAssigned": False, "error": str(e)}
