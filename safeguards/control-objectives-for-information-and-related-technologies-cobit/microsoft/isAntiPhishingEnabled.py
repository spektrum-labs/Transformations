"""
Transformation: isAntiPhishingEnabled
Vendor: Microsoft  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Whether anti-phishing related Secure Score controls are in a passing or active state.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAntiPhishingEnabled", "vendor": "Microsoft", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


ANTIPHISHING_CONTROLS = [
    "AntiPhishingPolicy",
    "EnableMailboxAudit",
    "BlockLegacyAuthentication",
    "EnableSafeLinksForEmail",
    "EnableSafeAttachments",
    "TurnOnATPForSPOTeamsODB",
    "SetOutboundSpamNotifications",
    "AntiSpoofingEnabled",
    "ImpersonationProtection"
]


def evaluate(data):
    try:
        scores = data.get("value", [])
        if not scores:
            return {
                "isAntiPhishingEnabled": False,
                "currentScore": 0,
                "maxScore": 0,
                "antiPhishingControlsFound": [],
                "antiPhishingControlsPassing": []
            }
        latest = scores[0]
        current_score = latest.get("currentScore", 0)
        max_score = latest.get("maxScore", 0)
        control_scores = latest.get("controlScores", [])
        found_controls = []
        passing_controls = []
        for cs in control_scores:
            ctrl_name = cs.get("controlName", "")
            ctrl_score = cs.get("score", 0)
            for keyword in ANTIPHISHING_CONTROLS:
                lower_ctrl = ctrl_name.lower()
                lower_kw = keyword.lower()
                if lower_kw in lower_ctrl:
                    found_controls.append(ctrl_name)
                    if ctrl_score and ctrl_score > 0:
                        passing_controls.append(ctrl_name)
                    break
        enabled = len(passing_controls) > 0
        return {
            "isAntiPhishingEnabled": enabled,
            "currentScore": current_score,
            "maxScore": max_score,
            "antiPhishingControlsFound": found_controls,
            "antiPhishingControlsPassing": passing_controls
        }
    except Exception as e:
        return {"isAntiPhishingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isAntiPhishingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("Anti-phishing controls are active in Microsoft Secure Score")
            passing = extra_fields.get("antiPhishingControlsPassing", [])
            if passing:
                pass_reasons.append("Passing anti-phishing controls: " + ", ".join(passing))
            pass_reasons.append("Secure Score: " + str(extra_fields.get("currentScore", 0)) + " / " + str(extra_fields.get("maxScore", 0)))
        else:
            fail_reasons.append("No anti-phishing Secure Score controls found in a passing state")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable anti-phishing policies in Microsoft Defender for Office 365, including anti-spoof protection and impersonation protection")
        combined = {criteriaKey: result_value}
        for k in extra_fields:
            combined[k] = extra_fields[k]
        return create_response(
            result=combined, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, "currentScore": extra_fields.get("currentScore", 0), "maxScore": extra_fields.get("maxScore", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
