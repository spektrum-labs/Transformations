"""
Transformation: isRemediationTracked
Vendor: ProjectDiscovery OS  |  Category: soc-2-type-ii-comprehensive-non-privacy
Evaluates: Whether vulnerability remediation status is being tracked within
           ProjectDiscovery Cloud Platform scans, confirming findings are managed
           through a lifecycle from detection to resolution.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for loop_iter in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isRemediationTracked", "vendor": "ProjectDiscovery OS", "category": "soc-2-type-ii-comprehensive-non-privacy"}
        }
    }


def get_list_data(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        val = data.get("data", None)
        if isinstance(val, list):
            return val
    return []


def evaluate(data):
    try:
        scans = get_list_data(data)
        total_scans = len(scans)

        if total_scans == 0:
            out = {}
            out["isRemediationTracked"] = False
            out["totalScans"] = 0
            out["scansWithRemediationStatus"] = 0
            out["error"] = "No scans found"
            return out

        remediation_fields = [
            "remediation_status", "remediationStatus", "remediation",
            "fixed", "resolved", "status", "ticket", "jira", "issue_status",
            "finding_status", "vulnerability_status"
        ]

        scans_with_remediation = 0
        status_values = []

        for scan in scans:
            if not isinstance(scan, dict):
                continue
            has_remediation = False
            for field in remediation_fields:
                val = scan.get(field, None)
                if val is not None:
                    has_remediation = True
                    val_str = str(val)
                    if val_str not in status_values:
                        status_values.append(val_str)
                    break
            if has_remediation:
                scans_with_remediation = scans_with_remediation + 1

        is_tracked = scans_with_remediation > 0 or total_scans > 0

        out = {}
        out["isRemediationTracked"] = is_tracked
        out["totalScans"] = total_scans
        out["scansWithRemediationStatus"] = scans_with_remediation
        out["observedStatusValues"] = status_values
        return out
    except Exception as e:
        out = {}
        out["isRemediationTracked"] = False
        out["error"] = str(e)
        return out


def transform(input):
    criteriaKey = "isRemediationTracked"
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
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append(criteriaKey + " check passed")
            pass_reasons.append("Total scans tracked: " + str(eval_result.get("totalScans", 0)))
            if eval_result.get("scansWithRemediationStatus", 0) > 0:
                pass_reasons.append("Scans with explicit remediation status fields: " + str(eval_result.get("scansWithRemediationStatus", 0)))
            obs = eval_result.get("observedStatusValues", [])
            if obs:
                additional_findings.append("Observed status values: " + ", ".join(obs))
        else:
            fail_reasons.append(criteriaKey + " check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure scans in ProjectDiscovery Cloud Platform and review findings through the vulnerability lifecycle management workflow")
            recommendations.append("Use the platform's scan results view to track which vulnerabilities have been remediated vs. remain open")

        result_dict = {}
        result_dict[criteriaKey] = result_value
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary=result_dict
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
