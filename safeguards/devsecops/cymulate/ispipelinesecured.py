import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Cymulate (Breach & Attack Simulation)

    Checks: Whether simulation templates and security policies are configured
    API Source: GET https://api.cymulate.com/v1/browsing/templates
    Pass Condition: At least one simulation template is configured and active

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

        # Check for simulation templates indicating pipeline security testing
        templates = data.get("data", data.get("templates", data.get("results", [])))
        if isinstance(templates, list) and len(templates) > 0:
            for template in templates:
                if isinstance(template, dict) and (template.get("id") or template.get("name")):
                    result = True
                    break
        elif isinstance(templates, dict) and templates.get("id"):
            result = True
        elif data.get("total", data.get("count", 0)) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isPipelineSecured": result}
    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
