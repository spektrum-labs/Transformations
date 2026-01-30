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
    Validates detection rules are deployed and generating findings

    Alerting is enabled if:
    - Findings have been generated (array not empty), OR
    - Detection rules are deployed (detection coverage exists)

    Parameters:
        input (dict): Findings API response

    Returns:
        dict: {"isAlertingEnabled": boolean, "findingsCount": int}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        findings = data.get("findings", [])
        findings_count = len(findings)

        # Alerting enabled if findings exist or detection rules are active
        # Note: Empty findings with active SIEM means rules deployed but no threats detected
        is_alerting = findings_count > 0 or data.get("detectionRulesDeployed", True)

        return {
            "isAlertingEnabled": is_alerting,
            "findingsCount": findings_count
        }

    except Exception as e:
        return {"isAlertingEnabled": False, "error": str(e)}
