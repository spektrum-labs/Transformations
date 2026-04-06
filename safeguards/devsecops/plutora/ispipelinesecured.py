import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Plutora

    Checks: Whether environment governance and deployment policies are configured
    API Source: {baseURL}/api/v1/environments
    Pass Condition: At least one environment exists with status tracking enabled

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPipelineSecured": boolean, "totalEnvironments": int, "managedEnvironments": int}
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
        environments = data if isinstance(data, list) else data.get("data", data.get("items", data.get("results", [])))

        if not isinstance(environments, list):
            environments = []

        total = len(environments)
        managed = [
            env for env in environments
            if isinstance(env, dict) and (
                env.get("status", "")
                or env.get("environmentStatus", "")
                or env.get("isSharedEnvironment") is not None
            )
        ]

        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isPipelineSecured": result,
            "totalEnvironments": total,
            "managedEnvironments": len(managed)
        }

    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
