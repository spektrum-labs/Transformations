"""
Transformation: isBackupEnabledForCriticalSystems
Vendor: Sophos  |  Category: Backups
Evaluates: Verifies that backup and data protection products are assigned and
actively running on critical system endpoints (servers) by checking
assignedProducts and health.services.serviceDetails.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupEnabledForCriticalSystems", "vendor": "Sophos", "category": "Backups"}
        }
    }


def endpoint_has_backup(endpoint):
    assigned = endpoint.get("assignedProducts", [])
    for product in assigned:
        code = product.get("code", "").lower()
        license_code = product.get("licenseCode", "").lower()
        if "backup" in code or "backup" in license_code:
            return True
    health = endpoint.get("health", {})
    services = health.get("services", {})
    service_details = services.get("serviceDetails", [])
    for svc in service_details:
        svc_name = svc.get("name", "").lower()
        if "backup" in svc_name:
            return True
    return False


def evaluate(data):
    try:
        items = data.get("items", [])
        if not items:
            return {
                "isBackupEnabledForCriticalSystems": False,
                "totalEndpoints": 0,
                "totalCriticalSystems": 0,
                "criticalSystemsWithBackup": 0,
                "scoreInPercentage": 0
            }

        total = len(items)
        critical_systems = []
        for ep in items:
            ep_type = ep.get("type", "").lower()
            if ep_type == "server":
                critical_systems.append(ep)

        if not critical_systems:
            critical_systems = items

        total_critical = len(critical_systems)
        backup_count = 0
        protected_hostnames = []
        unprotected_hostnames = []

        for ep in critical_systems:
            hostname = ep.get("hostname", ep.get("id", "unknown"))
            if endpoint_has_backup(ep):
                backup_count = backup_count + 1
                protected_hostnames.append(hostname)
            else:
                unprotected_hostnames.append(hostname)

        score = int((backup_count / total_critical) * 100) if total_critical > 0 else 0
        result = backup_count > 0 and backup_count == total_critical

        return {
            "isBackupEnabledForCriticalSystems": result,
            "totalEndpoints": total,
            "totalCriticalSystems": total_critical,
            "criticalSystemsWithBackup": backup_count,
            "scoreInPercentage": score,
            "protectedSystems": protected_hostnames,
            "unprotectedSystems": unprotected_hostnames
        }
    except Exception as e:
        return {"isBackupEnabledForCriticalSystems": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupEnabledForCriticalSystems"
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

        total_critical = extra_fields.get("totalCriticalSystems", 0)
        backup_count = extra_fields.get("criticalSystemsWithBackup", 0)
        score = extra_fields.get("scoreInPercentage", 0)

        if result_value:
            pass_reasons.append("All critical systems have backup products assigned and active")
            pass_reasons.append("Protected systems: " + str(backup_count) + " of " + str(total_critical) + " (" + str(score) + "%)")
        else:
            fail_reasons.append("Not all critical systems have backup enabled")
            fail_reasons.append("Coverage: " + str(backup_count) + " of " + str(total_critical) + " critical systems (" + str(score) + "%)")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Assign Sophos backup/data protection products to all server-class endpoints")
            recommendations.append("Review unprotected systems: " + ", ".join(extra_fields.get("unprotectedSystems", [])))
            unprotected = extra_fields.get("unprotectedSystems", [])
            if unprotected:
                additional_findings.append("Unprotected critical systems: " + ", ".join(unprotected))

        result_dict = {"isBackupEnabledForCriticalSystems": result_value}
        for k, v in extra_fields.items():
            result_dict[k] = v

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalCriticalSystems": total_critical, "criticalSystemsWithBackup": backup_count}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
