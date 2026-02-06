import json
import ast


def _parse_input(input):
    if isinstance(input, str):
        try:
            parsed = ast.literal_eval(input)
            if isinstance(parsed, dict):
                return parsed
        except:
            pass
        try:
            input = input.replace("'", '"')
            return json.loads(input)
        except:
            raise ValueError("Invalid input format")
    if isinstance(input, bytes):
        return json.loads(input.decode("utf-8"))
    if isinstance(input, dict):
        return input
    raise ValueError("Input must be JSON string, bytes, or dict")


def transform(input):
    """
    Verifies log retention meets compliance requirements

    Compliance requirement: 365 days retention
    - Free SIEM: 14 days (non-compliant)
    - SIEM Starter: 90 days (non-compliant)
    - Detect/Response/Automate/XDR: 365 days (compliant)

    Parameters:
        input (dict): Account info response

    Returns:
        dict: {"isLogRetentionCompliant": boolean, "retentionDays": int}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        retention_days = data.get("retentionDays", 0)
        license_edition = data.get("license", {}).get("edition", "").lower()

        # Map editions to retention
        retention_map = {
            "free": 14,
            "siem starter": 90,
            "detect": 365,
            "response": 365,
            "automate": 365,
            "xdr platform": 365
        }

        if retention_days == 0:
            for edition, days in retention_map.items():
                if edition in license_edition:
                    retention_days = days
                    break

        is_compliant = retention_days >= 365

        return {
            "isLogRetentionCompliant": is_compliant,
            "retentionDays": retention_days,
            "edition": license_edition
        }

    except Exception as e:
        return {"isLogRetentionCompliant": False, "error": str(e)}
