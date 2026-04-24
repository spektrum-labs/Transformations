"""
Transformation: isBackupEnabled
Vendor: Rubrik  |  Category: Backup
Evaluates: Whether backup policies (SLA Domains) are active and protecting objects in Rubrik.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupEnabled", "vendor": "Rubrik", "category": "Backup"}
        }
    }


def evaluate(data):
    try:
        sla_list = []
        if isinstance(data, dict):
            if "data" in data and isinstance(data["data"], list):
                sla_list = data["data"]
            elif "slaDomains" in data and isinstance(data["slaDomains"], list):
                sla_list = data["slaDomains"]
            elif "backupEnabled" in data:
                enabled = bool(data["backupEnabled"])
                return {"isBackupEnabled": enabled, "totalSlaDomains": 0, "protectedObjectCount": 0}
            elif "isEnabled" in data:
                enabled = bool(data["isEnabled"])
                return {"isBackupEnabled": enabled, "totalSlaDomains": 0, "protectedObjectCount": 0}
        elif isinstance(data, list):
            sla_list = data

        total_domains = len(sla_list)
        total_protected = 0
        active_domains = 0

        for domain in sla_list:
            if not isinstance(domain, dict):
                continue
            num_protected = domain.get("numProtectedObjects", domain.get("protectedObjectCount", 0))
            if num_protected is None:
                num_protected = 0
            total_protected = total_protected + num_protected
            is_active = domain.get("isActive", domain.get("enabled", True))
            if is_active:
                active_domains = active_domains + 1

        backup_enabled = total_domains > 0 and active_domains > 0

        return {
            "isBackupEnabled": backup_enabled,
            "totalSlaDomains": total_domains,
            "activeSlaDomains": active_domains,
            "totalProtectedObjects": total_protected
        }
    except Exception as e:
        return {"isBackupEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupEnabled"
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
        additional_findings = []
        if result_value:
            pass_reasons.append("Rubrik backup is enabled: active SLA domains found")
            additional_findings.append("Active SLA domains: " + str(extra_fields.get("activeSlaDomains", 0)))
            additional_findings.append("Protected objects: " + str(extra_fields.get("totalProtectedObjects", 0)))
        else:
            fail_reasons.append("No active Rubrik SLA domains found — backup may not be enabled")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Create and activate SLA Domain policies in Rubrik to ensure backup is running")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalSlaDomains": extra_fields.get("totalSlaDomains", 0), "activeSlaDomains": extra_fields.get("activeSlaDomains", 0)}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
