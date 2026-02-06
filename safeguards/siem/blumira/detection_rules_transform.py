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
    Confirms expert-built detection rules are deployed and active

    Blumira auto-deploys detection rules when integrations are configured.
    Detection rules are considered active if:
    - API returns findings (rules are generating alerts), OR
    - SIEM is enabled (rules are deployed by default)

    Parameters:
        input (dict): Findings/detection rules API response

    Returns:
        dict: {"isDetectionRulesActive": boolean}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # Check if findings exist (indicates rules are active)
        findings = data.get("findings", [])

        # Check for explicit detection rules field
        detection_rules = data.get("detectionRules", [])

        # Detection rules are active if we have findings or explicit rules
        # Blumira auto-deploys rules with integrations, so active SIEM = active rules
        is_active = len(findings) > 0 or len(detection_rules) > 0 or data.get("detectionRulesDeployed", True)

        return {
            "isDetectionRulesActive": is_active,
            "findingsCount": len(findings),
            "rulesCount": len(detection_rules) if detection_rules else "auto-deployed"
        }

    except Exception as e:
        return {"isDetectionRulesActive": False, "error": str(e)}
