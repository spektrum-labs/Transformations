"""
Transformation: isPatchManagementValid
Vendor: ManageEngine Endpoint Central (Cloud)  |  Category: EPP
Evaluates: Whether patch compliance and system health meet remediation thresholds.
Source: GET /api/1.4/patch/summary + GET /api/1.4/patch/healthpolicy

Endpoint Central Cloud wraps every payload in `message_response`, which the
previous generic wrapper list did not cover, so the transform read an empty dict
and always returned False. Field names below are taken from live Cloud responses.
"""
import json
from datetime import datetime

ENVELOPE_KEYS = ["api_response", "response", "result", "apiResponse", "Output", "message_response"]


def unwrap(data):
    """Strip known response envelopes, including ManageEngine's message_response."""
    if not isinstance(data, dict):
        return data
    for attempt in range(4):
        moved = False
        for key in ENVELOPE_KEYS:
            inner = data.get(key)
            if isinstance(inner, dict):
                data = inner
                moved = True
                break
        if not moved:
            break
    return data


def section(data, name):
    """Return dict `name`, tolerating one extra nesting level.

    Works whether the caller hands us message_response.summary directly or the
    still-enveloped payload, so the transform is correct with or without a
    returnSpec on the integration definition.
    """
    if not isinstance(data, dict):
        return {}
    direct = data.get(name)
    if isinstance(direct, dict):
        return direct
    for value in data.values():
        if isinstance(value, dict):
            nested = value.get(name)
            if isinstance(nested, dict):
                return nested
    return {}


def num(source, name, fallback=0):
    """Read an int off a dict, tolerating strings and missing keys."""
    try:
        value = source.get(name, fallback)
        if value is None:
            return fallback
        return int(value)
    except Exception:
        return fallback


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return unwrap(input_data["data"]), input_data["validation"]
    return unwrap(input_data), {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isPatchManagementValid", "vendor": "ManageEngine", "category": "EPP"}
        }
    }

PATCH_COMPLIANCE_THRESHOLD = 80.0
SYSTEM_HEALTH_THRESHOLD = 80.0


def evaluate(data):
    """Validate patch posture against compliance and system-health thresholds."""
    try:
        patch_summary = section(data, "patch_summary")
        system_summary = section(data, "system_summary")
        severity = section(data, "missing_patch_severity_summary")
        db_summary = section(data, "vulnerability_db_summary")
        highly_vulnerable_policy = section(data, "highly_vulnerable")

        installed = num(patch_summary, "installed_patches")
        applicable = num(patch_summary, "applicable_patches")
        missing = num(patch_summary, "missing_patches")

        total_systems = num(system_summary, "total_systems")
        healthy = num(system_summary, "healthy_systems")
        highly_vulnerable = num(system_summary, "highly_vulnerable_systems")
        moderately_vulnerable = num(system_summary, "moderately_vulnerable_systems")

        critical_missing = num(severity, "critical_count")
        important_missing = num(severity, "important_count")

        patch_compliance = 0.0
        if applicable > 0:
            patch_compliance = (installed * 100.0) / applicable

        system_health = 0.0
        if total_systems > 0:
            system_health = (healthy * 100.0) / total_systems

        issues = []
        is_valid = True

        if applicable == 0 and total_systems == 0:
            is_valid = False
            issues.append("No patch data available")

        if patch_compliance < PATCH_COMPLIANCE_THRESHOLD:
            is_valid = False
            issues.append("Patch compliance is " + str(round(patch_compliance, 1))
                          + "% - below the " + str(PATCH_COMPLIANCE_THRESHOLD) + "% threshold")

        if system_health < SYSTEM_HEALTH_THRESHOLD:
            is_valid = False
            issues.append("System health is " + str(round(system_health, 1)) + "% - "
                          + str(highly_vulnerable) + " highly vulnerable and "
                          + str(moderately_vulnerable) + " moderately vulnerable systems")

        if critical_missing > 0:
            is_valid = False
            issues.append(str(critical_missing) + " critical patches are missing")

        findings = []
        if bool(db_summary.get("is_auto_db_update_disabled", False)):
            findings.append("Automatic vulnerability database updates are disabled")
        if highly_vulnerable_policy:
            findings.append("Health policy thresholds are configured")

        pass_reasons = []
        recommendations = []
        if is_valid:
            pass_reasons.append("Patch compliance " + str(round(patch_compliance, 1))
                                + "% and system health " + str(round(system_health, 1)) + "%")
        else:
            if critical_missing > 0:
                recommendations.append("Deploy the " + str(critical_missing)
                                       + " missing critical patches as the first priority")
            if important_missing > 0:
                recommendations.append("Schedule remediation for " + str(important_missing)
                                       + " missing important patches")
            if system_health < SYSTEM_HEALTH_THRESHOLD:
                recommendations.append("Bring vulnerable systems into compliance to raise system health above "
                                       + str(SYSTEM_HEALTH_THRESHOLD) + "%")

        return {
            "isPatchManagementValid": is_valid,
            "patchCompliance": round(patch_compliance, 2),
            "systemHealth": round(system_health, 2),
            "totalSystems": total_systems,
            "healthySystems": healthy,
            "highlyVulnerableSystems": highly_vulnerable,
            "moderatelyVulnerableSystems": moderately_vulnerable,
            "installedPatches": installed,
            "applicablePatches": applicable,
            "missingPatches": missing,
            "missingCriticalPatches": critical_missing,
            "missingImportantPatches": important_missing,
            "issues": issues,
            "passReasons": pass_reasons,
            "failReasons": issues,
            "recommendations": recommendations,
            "additionalFindings": findings,
        }
    except Exception as e:
        return {"isPatchManagementValid": False, "error": str(e)}


def transform(input):
    criteriaKey = "isPatchManagementValid"
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
        meta_keys = ["error", "passReasons", "failReasons", "recommendations", "additionalFindings"]
        extra_fields = {k: v for k, v in eval_result.items()
                        if k != criteriaKey and k not in meta_keys}

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=eval_result.get("passReasons", []),
            fail_reasons=eval_result.get("failReasons", []),
            recommendations=eval_result.get("recommendations", []),
            additional_findings=eval_result.get("additionalFindings", []),
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
