import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Terraform Cloud (HashiCorp Terraform Cloud)

    Checks: Whether the organization entitlement set confirms an active subscription
    API Source: GET https://app.terraform.io/api/v2/organizations/{organizationName}/entitlement-set
    Pass Condition: API returns valid entitlement data confirming active plan

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

        # A valid entitlement-set response confirms active Terraform Cloud subscription
        entitlement = data.get("data", data)
        if isinstance(entitlement, dict):
            attributes = entitlement.get("attributes", entitlement)
            state_storage = attributes.get("state-storage", None)
            operations = attributes.get("operations", None)
            ent_id = entitlement.get("id", "")
            if state_storage is not None or operations is not None or ent_id:
                result = True
        elif data.get("id") or data.get("type") == "entitlement-sets":
            result = True
        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
