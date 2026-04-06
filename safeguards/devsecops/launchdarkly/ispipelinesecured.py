import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for LaunchDarkly

    Checks: Whether environment-level controls and approval workflows are configured
    API Source: https://app.launchdarkly.com/api/v2/projects/{projectKey}/environments
    Pass Condition: At least one environment has requireComments or confirmChanges enabled

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPipelineSecured": boolean, "totalEnvironments": int, "securedEnvironments": int}
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
        environments = data.get("items", data.get("data", data.get("results", [])))

        if not isinstance(environments, list):
            environments = []

        total = len(environments)
        secured = [
            env for env in environments
            if isinstance(env, dict) and (
                env.get("requireComments", False)
                or env.get("confirmChanges", False)
                or env.get("approvalSettings", {}).get("required", False)
            )
        ]

        result = len(secured) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isPipelineSecured": result,
            "totalEnvironments": total,
            "securedEnvironments": len(secured)
        }

    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
