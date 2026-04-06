import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Entrust Certificate Services (PKI / Certificate Management)

    Checks: Whether certificate issuance policies are configured
    API Source: GET https://api.managed.entrust.com/v1/policies
    Pass Condition: At least one certificate policy is defined and active

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

        # Check for certificate issuance policies
        policies = data.get("policies", data.get("data", data.get("results", [])))
        if isinstance(policies, list) and len(policies) > 0:
            for policy in policies:
                if isinstance(policy, dict) and (policy.get("id") or policy.get("name") or policy.get("policyId")):
                    result = True
                    break
        elif isinstance(policies, dict) and (policies.get("id") or policies.get("policyId")):
            result = True
        elif data.get("total", data.get("count", 0)) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isPipelineSecured": result}
    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
