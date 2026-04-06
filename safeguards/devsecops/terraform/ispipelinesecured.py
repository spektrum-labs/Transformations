import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for HCP Terraform (Infrastructure as Code)

    Checks: Whether Sentinel or OPA policies are enforced on infrastructure changes
    API Source: GET https://app.terraform.io/api/v2/organizations/{organizationName}/policies
    Pass Condition: At least one policy exists

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

        # Check for Sentinel/OPA policies
        policies = data.get("data", [])
        if isinstance(policies, list) and len(policies) > 0:
            for policy in policies:
                if isinstance(policy, dict):
                    attributes = policy.get("attributes", {})
                    name = attributes.get("name", policy.get("id", ""))
                    if name:
                        result = True
                        break
        elif data.get("meta", {}).get("pagination", {}).get("total-count", 0) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isPipelineSecured": result}
    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
