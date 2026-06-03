"""
Transformation: compliancepercentage
Vendor: Cloud Security
Category: Cloud Security / Compliance

Evaluates the compliance percentage of Cloud Security Compliance findings.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
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
                "transformationId": "compliancepercentage",
                "vendor": "Cloud Security",
                "category": "Cloud Security"
            }
        }
    }


# AWS Security Hub associated-standard identifiers used to scope each score.
CIS_STANDARD = "cis-aws-foundations-benchmark"
FSBP_STANDARD = "aws-foundational-security-best-practices"


def _is_suppressed(finding):
    """True when a Security Hub finding is suppressed (excluded from AWS scoring)."""
    if not isinstance(finding, dict):
        return False
    workflow = finding.get("Workflow")
    if isinstance(workflow, dict):
        return str(workflow.get("Status", "")).upper() == "SUPPRESSED"
    return False


def _matches_standard(finding, standard):
    """Whether a finding is associated with the given standard.

    Returns True/False when the finding carries AssociatedStandards, or None
    when the finding has no standard association (so callers can fall back to
    legacy, standard-agnostic behaviour for non-Security-Hub inputs).
    """
    compliance = finding.get("Compliance") if isinstance(finding, dict) else None
    if not isinstance(compliance, dict):
        return None
    standards = compliance.get("AssociatedStandards") or []
    ids = [str(s.get("StandardsId")) for s in standards
           if isinstance(s, dict) and s.get("StandardsId")]
    if not ids:
        return None
    return any(standard in sid for sid in ids)


def _score_by_control(findings):
    """Score findings per security control (CIS/FSBP scoring is per-control).

    Resource-level duplicates of the same control collapse to one result; a
    control passes only if all of its findings pass. Only PASSED/FAILED
    findings count toward the score (WARNING/NOT_AVAILABLE are ignored, matching
    AWS Security Hub).
    """
    control_passed = {}
    for obj in findings:
        compliance = obj.get("Compliance") if isinstance(obj, dict) else None
        if not isinstance(compliance, dict) or "Status" not in compliance:
            continue
        status = str(compliance["Status"]).lower()
        if status not in ("passed", "failed"):
            continue
        control_id = compliance.get("SecurityControlId") or obj.get("Id") or id(obj)
        passed = status == "passed"
        control_passed[control_id] = control_passed.get(control_id, True) and passed

    passed_count = sum(1 for ok in control_passed.values() if ok)
    failed_count = len(control_passed) - passed_count
    total = len(control_passed)
    percentage = int((passed_count / total) * 100) if total > 0 else 0
    return percentage, passed_count, failed_count, total


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"compliancePercentage": 0, "CIScompliancePercentage": 0},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Handle Findings array
        findings = []
        if isinstance(data, dict) and 'Findings' in data:
            findings = data['Findings']
        elif isinstance(data, list):
            findings = data

        # Exclude suppressed findings — AWS Security Hub omits them from its
        # security score, so the IAM.6 (SUPPRESSED) failure should not count.
        active = [obj for obj in findings if not _is_suppressed(obj)]

        # Scope each score to its own standard so the CIS and FSBP keys are not
        # conflated. Findings without an AssociatedStandards block (non Security
        # Hub inputs) fall back to legacy, standard-agnostic scoring.
        cis_findings = [obj for obj in active if _matches_standard(obj, CIS_STANDARD)]
        fsbp_findings = [obj for obj in active if _matches_standard(obj, FSBP_STANDARD)]
        if not cis_findings and not fsbp_findings:
            cis_findings = active
            fsbp_findings = active

        cis_percentage, cis_passed, cis_failed, cis_total = _score_by_control(cis_findings)
        fsbp_percentage, _, _, _ = _score_by_control(fsbp_findings)

        if cis_percentage >= 80:
            pass_reasons.append(f"Good compliance level: {cis_percentage}% ({cis_passed} passed, {cis_failed} failed)")
        elif cis_percentage >= 50:
            fail_reasons.append(f"Moderate compliance level: {cis_percentage}%")
            recommendations.append("Address failed compliance findings to improve security posture")
        else:
            fail_reasons.append(f"Low compliance level: {cis_percentage}%")
            recommendations.append("Urgently address compliance failures to meet security requirements")

        return create_response(
            result={
                "compliancePercentage": fsbp_percentage,
                "CIScompliancePercentage": cis_percentage,
                "totalPassed": cis_passed,
                "totalFailed": cis_failed,
                "totalFindings": cis_total
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "compliancePercentage": fsbp_percentage,
                "CIScompliancePercentage": cis_percentage,
                "totalPassed": cis_passed,
                "totalFailed": cis_failed,
                "totalFindings": cis_total
            }
        )

    except Exception as e:
        return create_response(
            result={"compliancePercentage": 0, "CIScompliancePercentage": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
