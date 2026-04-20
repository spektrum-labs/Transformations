"""
Transformation: isBackupEnabled
Vendor: Rubrik  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Whether backup policies (SLA Domains) are configured in Rubrik CDM.
A non-empty data array from GET /api/v1/sla_domain indicates that one or more SLA Domain
backup policies are active, confirming backups are enabled.
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
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isBackupEnabled",
                "vendor": "Rubrik",
                "category": "control-objectives-for-information-and-related-technologies-cobit"
            }
        }
    }


def evaluate(data):
    try:
        sla_domains = data.get("data", [])
        if not isinstance(sla_domains, list):
            sla_domains = []

        total_domains = len(sla_domains)
        is_enabled = total_domains > 0

        domain_names = []
        for domain in sla_domains:
            name = domain.get("name", "")
            if name:
                domain_names.append(name)

        return {
            "isBackupEnabled": is_enabled,
            "totalSlaDomains": total_domains,
            "slaDomainNames": domain_names
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
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        total_domains = eval_result.get("totalSlaDomains", 0)
        domain_names = eval_result.get("slaDomainNames", [])

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append(
                "Rubrik CDM has " + str(total_domains) + " active SLA Domain backup polic" +
                ("ies" if total_domains != 1 else "y") + " configured, confirming backups are enabled."
            )
            if domain_names:
                additional_findings.append("Active SLA Domains: " + ", ".join(domain_names))
        else:
            fail_reasons.append(
                "No SLA Domain backup policies were found in Rubrik CDM. "
                "The GET /api/v1/sla_domain response returned an empty data array."
            )
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            recommendations.append(
                "Create at least one SLA Domain in Rubrik CDM to define backup schedules "
                "and retention policies for your protected workloads."
            )

        return create_response(
            result={
                criteriaKey: result_value,
                "totalSlaDomains": total_domains,
                "slaDomainNames": domain_names
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalSlaDomains": total_domains,
                "isBackupEnabled": result_value
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
