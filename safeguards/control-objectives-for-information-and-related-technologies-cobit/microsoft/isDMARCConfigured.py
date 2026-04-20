"""
Transformation: isDMARCConfigured
Vendor: Microsoft  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Checks secure score control profiles for a DMARC-related control and verifies
implementation status to confirm DMARC policies are configured for tenant email domains
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isDMARCConfigured", "vendor": "Microsoft", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def evaluate(data):
    try:
        profiles = data.get("value", [])
        dmarc_profile = None
        for profile in profiles:
            title = profile.get("title", "")
            control_id = profile.get("id", "")
            if "dmarc" in title.lower() or "dmarc" in control_id.lower():
                dmarc_profile = profile
                break
        if dmarc_profile is None:
            return {
                "isDMARCConfigured": False,
                "reason": "No DMARC-related control profile found in Secure Score",
                "dmarcControlId": None,
                "dmarcImplementationStatus": None
            }
        impl_status = dmarc_profile.get("implementationStatus", "notImplemented")
        configured = impl_status in ["implemented", "thirdParty", "alternativeMitigationAccepted"]
        return {
            "isDMARCConfigured": configured,
            "dmarcControlId": dmarc_profile.get("id", ""),
            "dmarcControlTitle": dmarc_profile.get("title", ""),
            "dmarcImplementationStatus": impl_status
        }
    except Exception as e:
        return {"isDMARCConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isDMARCConfigured"
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
        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error" and k != "reason":
                extra_fields[k] = eval_result[k]
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append(criteriaKey + " check passed")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append(criteriaKey + " check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if "reason" in eval_result:
                fail_reasons.append(eval_result["reason"])
            recommendations.append("Configure a DMARC policy (p=quarantine or p=reject) for all tenant email domains using your DNS provider and validate in the Microsoft 365 Defender portal")
        result_dict = {}
        result_dict[criteriaKey] = result_value
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        return create_response(
            result=result_dict, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary=result_dict)
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
