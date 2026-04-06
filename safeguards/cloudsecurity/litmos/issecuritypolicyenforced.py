import json
import ast


def transform(input):
    """
    Evaluates isSecurityPolicyEnforced for Litmos

    Checks: Whether security training courses are assigned and active
    API Source: {baseURL}/courses?source={source}&limit=1000&format=json
    Pass Condition: At least 1 active training course exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityPolicyEnforced": boolean, "activeCourses": int, "totalCourses": int}
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
        courses = data if isinstance(data, list) else data.get("data", data.get("courses", data.get("results", data.get("items", []))))

        if not isinstance(courses, list):
            return {
                "isSecurityPolicyEnforced": False,
                "activeCourses": 0,
                "totalCourses": 0,
                "error": "Unexpected courses response format"
            }

        total = len(courses)

        active = [
            c for c in courses
            if c.get("Active", False) is True
            or c.get("active", False) is True
            or str(c.get("Active", "")).lower() in ("true", "1")
        ]

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityPolicyEnforced": result,
            "activeCourses": len(active),
            "totalCourses": total
        }

    except Exception as e:
        return {"isSecurityPolicyEnforced": False, "error": str(e)}
