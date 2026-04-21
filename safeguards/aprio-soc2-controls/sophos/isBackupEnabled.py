"""
Transformation: isBackupEnabled
Vendor: Sophos  |  Category: aprio-soc2-controls
Evaluates: Whether backup/data-protection capabilities are enabled in Sophos Central
by inspecting the account health check 'protection' check results. A healthy protection
status indicates endpoint protection (including backup/recovery agents) is running.
"""
import json
from datetime import datetime

CRITERIA_KEY = "isBackupEnabled"
VENDOR = "Sophos"
CATEGORY = "aprio-soc2-controls"


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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": CRITERIA_KEY, "vendor": VENDOR, "category": CATEGORY}
        }
    }


def evaluate(data):
    try:
        checks = data.get("checks", {})
        overall = data.get("overall", "")

        if not isinstance(checks, dict):
            checks = {}

        protection_check = checks.get("protection", {})
        if not isinstance(protection_check, dict):
            protection_check = {}

        protection_good = protection_check.get("good", None)
        healthy_count = protection_check.get("healthy", 0)
        unhealthy_count = protection_check.get("unhealthy", 0)
        missing_count = protection_check.get("missing", 0)

        if protection_good is True:
            backup_enabled = True
        elif protection_good is False:
            backup_enabled = False
        else:
            overall_lower = overall.lower() if isinstance(overall, str) else ""
            backup_enabled = overall_lower in ["good", "ok", "healthy"]

        total_endpoints = healthy_count + unhealthy_count + missing_count
        protected_count = healthy_count

        return {
            CRITERIA_KEY: backup_enabled,
            "overallHealthStatus": overall,
            "protectionGood": protection_good,
            "protectedEndpoints": protected_count,
            "unprotectedEndpoints": unhealthy_count,
            "missingProtection": missing_count,
            "totalEndpoints": total_endpoints
        }

    except Exception as e:
        return {CRITERIA_KEY: False, "error": str(e)}


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={CRITERIA_KEY: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(CRITERIA_KEY, False)

        extra_fields = {k: v for k, v in eval_result.items() if k != CRITERIA_KEY and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        overall = eval_result.get("overallHealthStatus", "")
        protected = eval_result.get("protectedEndpoints", 0)
        unprotected = eval_result.get("unprotectedEndpoints", 0)
        missing = eval_result.get("missingProtection", 0)
        total = eval_result.get("totalEndpoints", 0)

        if result_value:
            pass_reasons.append("Sophos endpoint protection (backup/data-protection) is enabled and healthy.")
            pass_reasons.append("Account health check 'protection' status is good.")
            if total > 0:
                pass_reasons.append(
                    str(protected) + " of " + str(total) + " endpoints have active protection coverage."
                )
            if overall:
                additional_findings.append("Overall account health status: " + str(overall))
        else:
            fail_reasons.append("Sophos endpoint protection (backup/data-protection) is NOT confirmed healthy.")
            if unprotected > 0:
                fail_reasons.append(str(unprotected) + " endpoint(s) reported as unhealthy/unprotected.")
            if missing > 0:
                fail_reasons.append(str(missing) + " endpoint(s) have missing protection agents.")
            if overall:
                fail_reasons.append("Overall account health status: " + str(overall))
            recommendations.append("Review unhealthy endpoints in Sophos Central and ensure the protection policy is applied to all managed devices.")
            recommendations.append("Check that Sophos agents are installed and up-to-date on all endpoints.")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        return create_response(
            result={CRITERIA_KEY: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                CRITERIA_KEY: result_value,
                "overallHealthStatus": overall,
                "totalEndpoints": total,
                "protectedEndpoints": protected
            }
        )

    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
