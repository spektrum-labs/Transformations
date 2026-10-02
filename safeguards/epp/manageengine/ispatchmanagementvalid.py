"""
Transformation: isPatchManagementValid
Vendor: ManageEngine Endpoint Central (Cloud and on-premises)  |  Category: EPP
Evaluates: whether patch compliance and system health meet remediation thresholds and no critical patch is missing.
Source: workflow isPatchManagementValid, two independent reads merged under output keys
  patchSummary - GET /api/1.4/patch/summary
  healthPolicy - GET /api/1.4/patch/healthpolicy

Accepted input shapes:
  * {"patchSummary": <summary body>, "healthPolicy": <health policy body>}  (workflow steps with output keys + merge)
  * one envelope whose message_response holds "summary" and/or "healthpolicy" (merge without output keys, or a
    single read of the patch summary)
  * the same with message_response already stripped

The earlier workflow had no merge, so Integration-Service kept only the last step (the health policy). This
transform then found no patch summary, read every count as 0 and scored False with "No patch data available".
A missing read is now reported as not evaluated, never as a failed control.

Verdict (unchanged thresholds): valid when installed / applicable patches >= 80%, healthy / total systems >= 80%,
and no critical patch is missing.

Not evaluated (isPatchManagementValid None, dataCollection "error"): no JSON object; a vendor, auth or IS error
body in any part that is present; no patch summary; a required count missing or not a whole number
(installed_patches, applicable_patches, missing_patches, total_systems, healthy_systems, critical_count);
0 systems; 0 applicable patches while patches are reported missing.
"""
import json
from datetime import datetime

CRITERIA_KEY = "isPatchManagementValid"
PATCH_COMPLIANCE_THRESHOLD = 80.0
SYSTEM_HEALTH_THRESHOLD = 80.0
WRAPPERS = ["api_response", "response", "result", "apiResponse", "Output"]
SUMMARY_KEYS = ["patchSummary", "patch_summary_response", "getPatchSummary"]
POLICY_KEYS = ["healthPolicy", "health_policy_response", "getPatchHealthPolicy"]


def parse_input(input_data):
    if isinstance(input_data, bytes):
        input_data = input_data.decode("utf-8")
    if isinstance(input_data, str):
        input_data = json.loads(input_data)
    return input_data


def extract_input(input_data):
    validation = {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}
    data = input_data
    if isinstance(data, dict) and "data" in data and "validation" in data:
        validation = data["validation"] if isinstance(data["validation"], dict) else validation
        data = data["data"]
    for step in range(3):
        if not isinstance(data, dict):
            break
        moved = False
        for key in WRAPPERS:
            if key in data and isinstance(data.get(key), dict):
                data = data[key]
                moved = True
                break
        if not moved:
            break
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    api_errors=None, input_summary=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": CRITERIA_KEY, "vendor": "ManageEngine", "category": "EPP"},
        },
    }


def not_evaluated(reason, validation=None):
    result = {CRITERIA_KEY: None}
    return create_response(result, validation=validation, api_errors=[reason], fail_reasons=[reason],
                           input_summary=result)


def to_count(value):
    """A non-negative whole number from an int or a digit string; None for anything else."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float):
        return int(value) if value >= 0 and value == int(value) else None
    text = str(value).strip()
    if not text.isdigit():
        return None
    return int(text)


def truthy(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes")


def vendor_error(body, label):
    """The reason this part is not a successful vendor read, or None."""
    if not isinstance(body, dict):
        return "the " + label + " read returned no JSON object"
    if not body:
        return "the " + label + " read returned an empty body"
    if body.get("error") is True or body.get("errorType"):
        return "the " + label + " read failed: " + str(body.get("message") or body.get("errorType") or "error")
    if body.get("error_code") or body.get("errorCode"):
        return "ManageEngine returned " + str(body.get("error_code") or body.get("errorCode")) + " for the " + \
            label + ": " + str(body.get("error_description") or body.get("errorMessage") or body.get("message") or "")
    status = str(body.get("status") or "").strip().lower()
    if status and status != "success":
        return "ManageEngine answered the " + label + " with status " + status
    return None


def inner_of(body):
    """message_response when present, else the body itself (already unwrapped)."""
    inner = body.get("message_response")
    return inner if isinstance(inner, dict) else body


def summary_of(inner):
    """The patch summary section dict (holding patch_summary), or None."""
    summary = inner.get("summary")
    if isinstance(summary, dict) and isinstance(summary.get("patch_summary"), dict):
        return summary
    if isinstance(inner.get("patch_summary"), dict):
        return inner
    return None


def policy_of(inner):
    policy = inner.get("healthpolicy")
    if isinstance(policy, dict):
        return policy
    if isinstance(inner.get("highly_vulnerable"), dict):
        return inner
    return None


def first_key(data, names):
    for name in names:
        if name in data:
            return name
    return None


def read_parts(data):
    """(summary section, health policy, problem). problem is set when any present part failed."""
    if not isinstance(data, dict):
        return None, None, "the patch workflow returned no JSON object"
    if not data:
        return None, None, "the patch workflow returned an empty body"
    summary_key = first_key(data, SUMMARY_KEYS)
    policy_key = first_key(data, POLICY_KEYS)
    if summary_key or policy_key:
        summary = None
        policy = None
        if summary_key:
            problem = vendor_error(data[summary_key], "patch summary")
            if problem:
                return None, None, problem
            summary = summary_of(inner_of(data[summary_key]))
        if policy_key:
            problem = vendor_error(data[policy_key], "patch health policy")
            if problem:
                return None, None, problem
            policy = policy_of(inner_of(data[policy_key]))
        return summary, policy, None
    problem = vendor_error(data, "patch workflow")
    if problem:
        return None, None, problem
    inner = inner_of(data)
    return summary_of(inner), policy_of(inner), None


def count_in(section, name):
    if not isinstance(section, dict):
        return None
    return to_count(section.get(name))


def transform(input):
    try:
        data, validation = extract_input(parse_input(input))
    except Exception as exc:
        return not_evaluated("input could not be read: " + str(exc))
    try:
        summary, policy, problem = read_parts(data)
        if problem:
            return not_evaluated(problem, validation)
        if summary is None:
            reason = "the patch summary (GET /api/1.4/patch/summary) was not in the input"
            if policy is not None:
                reason = reason + "; only the health policy arrived, so patch compliance cannot be measured"
            return not_evaluated(reason, validation)

        patch_summary = summary.get("patch_summary")
        system_summary = summary.get("system_summary")
        severity = summary.get("missing_patch_severity_summary")
        db_summary = summary.get("vulnerability_db_summary") if isinstance(summary.get("vulnerability_db_summary"),
                                                                             dict) else {}

        installed = count_in(patch_summary, "installed_patches")
        applicable = count_in(patch_summary, "applicable_patches")
        missing = count_in(patch_summary, "missing_patches")
        total_systems = count_in(system_summary, "total_systems")
        healthy = count_in(system_summary, "healthy_systems")
        critical_missing = count_in(severity, "critical_count")
        needed = {"installed_patches": installed, "applicable_patches": applicable, "missing_patches": missing,
                  "total_systems": total_systems, "healthy_systems": healthy, "critical_count": critical_missing}
        absent = [name for name in needed if needed[name] is None]
        if absent:
            return not_evaluated("the patch summary is missing " + ", ".join(absent) +
                                 " (or it is not a whole number)", validation)
        if total_systems == 0:
            return not_evaluated("the patch summary reports 0 systems, so there is nothing to measure", validation)
        if applicable == 0 and missing > 0:
            return not_evaluated("the patch summary reports 0 applicable patches but " + str(missing) +
                                 " missing, which is inconsistent", validation)

        highly_vulnerable = count_in(system_summary, "highly_vulnerable_systems") or 0
        moderately_vulnerable = count_in(system_summary, "moderately_vulnerable_systems") or 0
        important_missing = count_in(severity, "important_count") or 0

        patch_compliance = 100.0 if applicable == 0 else (installed * 100.0) / applicable
        system_health = (healthy * 100.0) / total_systems

        issues = []
        if patch_compliance < PATCH_COMPLIANCE_THRESHOLD:
            issues.append("Patch compliance is " + str(round(patch_compliance, 1)) + "% - below the " +
                          str(PATCH_COMPLIANCE_THRESHOLD) + "% threshold")
        if system_health < SYSTEM_HEALTH_THRESHOLD:
            issues.append("System health is " + str(round(system_health, 1)) + "% - " + str(highly_vulnerable) +
                          " highly vulnerable and " + str(moderately_vulnerable) + " moderately vulnerable systems")
        if critical_missing > 0:
            issues.append(str(critical_missing) + " critical patches are missing")
        is_valid = not issues

        findings = []
        if truthy(db_summary.get("is_auto_db_update_disabled", False)):
            findings.append("Automatic vulnerability database updates are disabled")
        if policy is None:
            findings.append("The patch health policy was not in the input")
        elif isinstance(policy.get("highly_vulnerable"), dict):
            findings.append("Health policy thresholds are configured")

        recommendations = []
        if critical_missing > 0:
            recommendations.append("Deploy the " + str(critical_missing) +
                                   " missing critical patches as the first priority")
        if not is_valid and important_missing > 0:
            recommendations.append("Schedule remediation for " + str(important_missing) +
                                   " missing important patches")
        if system_health < SYSTEM_HEALTH_THRESHOLD:
            recommendations.append("Bring vulnerable systems into compliance to raise system health above " +
                                   str(SYSTEM_HEALTH_THRESHOLD) + "%")

        result = {
            CRITERIA_KEY: is_valid,
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
            "healthPolicyRead": policy is not None,
            "issues": issues,
        }
        pass_reasons = []
        if is_valid:
            pass_reasons.append("Patch compliance " + str(round(patch_compliance, 1)) + "% and system health " +
                                str(round(system_health, 1)) + "%, no critical patch missing")
        return create_response(result, validation=validation, pass_reasons=pass_reasons, fail_reasons=issues,
                               recommendations=recommendations, input_summary=result, additional_findings=findings)
    except Exception as exc:
        return not_evaluated("transformation error: " + str(exc), validation)
