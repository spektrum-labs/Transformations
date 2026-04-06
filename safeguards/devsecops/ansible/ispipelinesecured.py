import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Ansible Automation Platform

    Checks: Whether workflow job templates are configured for pipeline orchestration
    API Source: {baseURL}/api/v2/workflow_job_templates/
    Pass Condition: At least one workflow job template is configured

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPipelineSecured": boolean, "activeWorkflows": int, "totalWorkflows": int}
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
        workflows = data.get("results", data.get("data", data.get("workflow_job_templates", data.get("items", []))))

        if not isinstance(workflows, list):
            count = data.get("count", 0)
            if isinstance(count, int) and count > 0:
                return {
                    "isPipelineSecured": True,
                    "activeWorkflows": count,
                    "totalWorkflows": count
                }
            return {
                "isPipelineSecured": False,
                "activeWorkflows": 0,
                "totalWorkflows": 0,
                "error": "Unexpected response format"
            }

        total = len(workflows)
        active = []
        for wf in workflows:
            enabled = wf.get("enabled", wf.get("active", wf.get("status", "")))
            if enabled is True:
                active.append(wf)
            elif enabled is False:
                pass
            elif isinstance(enabled, str) and enabled.lower() in ("true", "active", "enabled"):
                active.append(wf)
            else:
                active.append(wf)

        result = len(active) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isPipelineSecured": result,
            "activeWorkflows": len(active),
            "totalWorkflows": total
        }

    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
