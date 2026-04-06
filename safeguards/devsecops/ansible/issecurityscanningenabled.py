import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for Ansible Automation Platform

    Checks: Whether job templates are configured for automation scanning
    API Source: {baseURL}/api/v2/job_templates/
    Pass Condition: At least one job template exists and is enabled

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean, "activeTemplates": int, "totalTemplates": int}
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
        templates = data.get("results", data.get("data", data.get("job_templates", data.get("items", []))))

        if not isinstance(templates, list):
            count = data.get("count", 0)
            if isinstance(count, int) and count > 0:
                return {
                    "isSecurityScanningEnabled": True,
                    "activeTemplates": count,
                    "totalTemplates": count
                }
            return {
                "isSecurityScanningEnabled": False,
                "activeTemplates": 0,
                "totalTemplates": 0,
                "error": "Unexpected response format"
            }

        total = len(templates)
        active = []
        for template in templates:
            enabled = template.get("enabled", template.get("active", template.get("status", "")))
            if enabled is True:
                active.append(template)
            elif enabled is False:
                pass
            elif isinstance(enabled, str) and enabled.lower() in ("true", "active", "enabled"):
                active.append(template)
            else:
                active.append(template)

        result = len(active) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityScanningEnabled": result,
            "activeTemplates": len(active),
            "totalTemplates": total
        }

    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
