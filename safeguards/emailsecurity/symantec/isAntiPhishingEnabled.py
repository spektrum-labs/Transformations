"""
Transformation: isAntiPhishingEnabled
Vendor: Symantec  |  Category: emailsecurity
Evaluates: Whether Anti-Phishing or Anti-Malware service is enabled in Symantec Email Security.cloud service configuration.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAntiPhishingEnabled", "vendor": "Symantec", "category": "emailsecurity"}
        }
    }


def evaluate(data):
    try:
        services = data.get("services", [])
        if not isinstance(services, list):
            services = []

        keywords = ["anti-phishing", "antiphishing", "anti_phishing", "anti-malware", "antimalware",
                    "threat isolation", "email threat", "malware", "phishing"]

        matched_name = ""
        matched_status = "not found"
        found = False

        for service in services:
            if not isinstance(service, dict):
                continue
            name = str(service.get("name", "")).lower()
            stype = str(service.get("type", "")).lower()
            status = str(service.get("status", "")).lower()
            enabled = service.get("enabled", False)
            active = status in ["active", "enabled", "true"] or enabled is True or str(enabled).lower() == "true"

            hit = False
            for kw in keywords:
                if kw in name or kw in stype:
                    hit = True
                    break

            if hit:
                matched_name = service.get("name", "unknown")
                matched_status = status
                if active:
                    found = True
                    break

        return {
            "isAntiPhishingEnabled": found,
            "matchedService": matched_name,
            "serviceStatus": matched_status,
            "totalServices": len(services)
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
            pass_reasons.append("Anti-phishing or anti-malware service is active in Symantec Email Security configuration.")
            pass_reasons.append("Matched service: " + str(extra_fields.get("matchedService", "")))
        else:
            fail_reasons.append("No active anti-phishing or anti-malware service found in service configuration.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable Anti-Phishing or Anti-Malware service in the Symantec Email Security.cloud ClientNet portal.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalServices": extra_fields.get("totalServices", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
