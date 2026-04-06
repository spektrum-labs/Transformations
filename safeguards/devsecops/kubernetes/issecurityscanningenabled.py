import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for Kubernetes

    Checks: Whether admission controllers and validating webhooks are configured
    API Source: {baseURL}/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations
    Pass Condition: At least one validating webhook configuration exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean, "webhookCount": int, "webhooks": list}
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
        items = data.get("items", [])

        if not isinstance(items, list):
            return {
                "isSecurityScanningEnabled": False,
                "webhookCount": 0,
                "webhooks": [],
                "error": "Unexpected response format"
            }

        webhook_names = [
            item.get("metadata", {}).get("name", "unknown")
            for item in items
            if isinstance(item, dict)
        ]

        result = len(webhook_names) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityScanningEnabled": result,
            "webhookCount": len(webhook_names),
            "webhooks": webhook_names
        }

    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
