import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for TeamCity (JetBrains CI/CD Server)

    Checks: Whether builds have been executed indicating CI/CD scanning is active
    API Source: GET {baseURL}/app/rest/builds?locator=count:10
    Pass Condition: At least one build exists in the build history

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean}
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
        result = False

        # Check for build history indicating CI/CD scanning
        builds = data.get("build", data.get("builds", []))
        if isinstance(builds, list) and len(builds) > 0:
            result = True
        elif data.get("count", 0) > 0:
            result = True
        elif data.get("href") and data.get("count") is not None:
            result = data.get("count", 0) > 0
        # -- END EVALUATION LOGIC --

        return {"isSecurityScanningEnabled": result}
    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
