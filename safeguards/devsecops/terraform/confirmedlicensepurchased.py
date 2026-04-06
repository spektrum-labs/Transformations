import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for HCP Terraform (Infrastructure as Code)

    Checks: Whether the Terraform organization is accessible and active
    API Source: GET https://app.terraform.io/api/v2/organizations/{organizationName}
    Pass Condition: API returns valid organization data confirming active subscription

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean}
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

        # A valid organization response confirms active HCP Terraform subscription
        org_data = data.get("data", data)
        if isinstance(org_data, dict):
            attributes = org_data.get("attributes", org_data)
            name = attributes.get("name", "")
            org_id = org_data.get("id", "")
            if name or org_id:
                result = True
        elif data.get("name") or data.get("id"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
