import json
import ast


def transform(input):
    """Evaluates confirmedLicensePurchased for SailPoint IdentityIQ (IAM)

    Checks: Whether a valid IdentityIQ instance is active by confirming
            the SCIM ServiceProviderConfig endpoint returns a valid response.
    API Source: GET {baseURL}/scim/v2/ServiceProviderConfig
    Pass Condition: API returns a valid ServiceProviderConfig resource.
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

        # ── EVALUATION LOGIC ──
        result = False

        # ServiceProviderConfig returns {"meta": {"resourceType": "ServiceProviderConfig"}, ...}
        meta = data.get("meta", {})
        resource_type = ""
        if isinstance(meta, dict):
            resource_type = meta.get("resourceType", "")

        status = data.get("status", data.get("licensePurchased", ""))

        if isinstance(resource_type, str) and len(resource_type) > 0:
            result = True
        elif isinstance(status, str) and len(status) > 0:
            result = True
        elif isinstance(status, bool):
            result = status

        # Check for SCIM schemas indicating active service
        schemas = data.get("schemas", [])
        if isinstance(schemas, list) and len(schemas) > 0:
            result = True

        # Check for patch/bulk/filter support indicating active SCIM service
        patch = data.get("patch", data.get("bulk", None))
        if isinstance(patch, dict):
            result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
