import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Lark (Bytedance)

    Checks: Whether the Lark tenant subscription is active
    API Source: https://open.larksuite.com/open-apis/tenant/v2/tenant/query
    Pass Condition: Tenant status is active or tenant data is returned

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "status": str, "tenantName": str}
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
        tenant = data.get("tenant", data.get("data", data))
        if isinstance(tenant, dict):
            status = tenant.get("status", "")
            active = tenant.get("active", False)
            tenant_name = tenant.get("name", tenant.get("display_name", "unknown"))
        else:
            status = data.get("status", "")
            active = data.get("active", False)
            tenant_name = data.get("name", "unknown")

        if isinstance(status, str):
            status = status.lower()

        valid_statuses = {"active", "enabled", "normal"}
        result = status in valid_statuses or active is True

        # Lark returns code 0 on success; a valid tenant response implies active
        code = data.get("code", -1)
        if not result and code == 0 and tenant_name != "unknown":
            result = True
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status,
            "tenantName": tenant_name
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
