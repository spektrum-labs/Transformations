"""
Transformation: isPatchManagementEnabled
Vendor: ManageEngine Endpoint Central (Cloud)  |  Category: EPP
Evaluates: Whether patch scanning and deployment are actively running.
Source: GET /api/1.4/patch/summary

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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isPatchManagementEnabled", "vendor": "ManageEngine", "category": "EPP"}
        }
    }


def evaluate(data):
    """Patch management is enabled when systems are being scanned AND patching activity exists."""
    try:
        patch_summary = section(data, "patch_summary")
        scan_summary = section(data, "patch_scan_summary")
        system_summary = section(data, "system_summary")
        apd_summary = section(data, "apd_summary")
        db_summary = section(data, "vulnerability_db_summary")

        installed = num(patch_summary, "installed_patches")
        applicable = num(patch_summary, "applicable_patches")
        missing = num(patch_summary, "missing_patches")
        scanned = num(scan_summary, "scanned_systems")
        unscanned = num(scan_summary, "unscanned_system_count")
        scan_failures = num(scan_summary, "scan_failure_count")
        total_systems = num(system_summary, "total_systems")
        apd_tasks = num(apd_summary, "number_of_apd_tasks")

        auto_db_disabled = bool(db_summary.get("is_auto_db_update_disabled", False))
        db_status = str(db_summary.get("last_db_update_status", ""))

        is_enabled = scanned > 0 and (installed > 0 or apd_tasks > 0)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        findings = []

        if is_enabled:
            pass_reasons.append(str(scanned) + " of " + str(total_systems) + " systems scanned for patches")
            pass_reasons.append(str(installed) + " patches installed, " + str(applicable) + " applicable")
            if apd_tasks > 0:
                pass_reasons.append(str(apd_tasks) + " automated patch deployment tasks configured")
        else:
            if scanned == 0:
                fail_reasons.append("No systems have been scanned for patches")
                recommendations.append("Run a patch scan under Patch Management > Scan Systems")
            else:
                fail_reasons.append("Systems are scanned but no patch deployment activity was found")
                recommendations.append("Configure an Automated Patch Deployment task")

        if auto_db_disabled:
            findings.append("Automatic vulnerability database updates are DISABLED (last status: "
                            + db_status + ")")
            recommendations.append("Re-enable automatic vulnerability database updates")
        if unscanned > 0:
            findings.append(str(unscanned) + " systems have never been scanned")
        if scan_failures > 0:
            findings.append(str(scan_failures) + " systems failed their most recent scan")

        return {
            "isPatchManagementEnabled": is_enabled,
            "scannedSystems": scanned,
            "unscannedSystems": unscanned,
            "totalSystems": total_systems,
            "installedPatches": installed,
            "applicablePatches": applicable,
            "missingPatches": missing,
            "automatedDeploymentTasks": apd_tasks,
            "autoDbUpdateDisabled": auto_db_disabled,
            "passReasons": pass_reasons,
            "failReasons": fail_reasons,
            "recommendations": recommendations,
            "additionalFindings": findings,
        }
    except Exception as e:
        return {"isPatchManagementEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isPatchManagementEnabled"
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
