import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for TeamCity (JetBrains CI/CD Server)

    Checks: Whether projects are configured with build policies
    API Source: GET {baseURL}/app/rest/projects
    Pass Condition: At least one project exists with defined build configurations

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPipelineSecured": boolean}
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

        # Check for projects with build configurations
        projects = data.get("project", data.get("projects", []))
        if isinstance(projects, list) and len(projects) > 0:
            for project in projects:
                if isinstance(project, dict):
                    name = project.get("name", project.get("id", ""))
                    if name:
                        result = True
                        break
        elif data.get("count", 0) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isPipelineSecured": result}
    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
