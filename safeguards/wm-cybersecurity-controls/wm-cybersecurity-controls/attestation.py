"""
Transformation: attestation
Vendor: WM - Cybersecurity Controls  |  Category: wm-cybersecurity-controls
Evaluates: All WM Cybersecurity Controls attestation answers. Mandatory controls must be answered
'Yes' to pass. Optional controls accept 'Yes' or 'No'. Returns True when all mandatory
attestations are satisfied.
"""
import json
from datetime import datetime


MANDATORY_FIELDS = [
    "attest_mfa",
    "attest_edr",
    "attest_pam",
    "attest_email_security",
    "attest_ir_plan",
    "attest_vuln_mgmt",
    "attest_backup",
    "attest_network_seg",
    "attest_sec_training",
    "attest_encryption",
    "attest_vendor_risk",
    "attest_access_control",
    "attest_logging",
    "attest_firewall",
]

MANDATORY_LABELS = {
    "attest_mfa": "Multi-Factor Authentication (MFA) Deployed",
    "attest_edr": "Endpoint Detection and Response (EDR) Deployed",
    "attest_pam": "Privileged Access Management (PAM) Controls in Place",
    "attest_email_security": "Email Security Controls Deployed",
    "attest_ir_plan": "Incident Response Plan in Place",
    "attest_vuln_mgmt": "Vulnerability Management Program Active",
    "attest_backup": "Data Backup and Recovery Controls in Place",
    "attest_network_seg": "Network Segmentation Implemented",
    "attest_sec_training": "Security Awareness Training Conducted",
    "attest_encryption": "Encryption of Data at Rest and in Transit",
    "attest_vendor_risk": "Third-Party Vendor Risk Management Program",
    "attest_access_control": "Access Control and Identity Management Policies",
    "attest_logging": "Security Logging and Monitoring Active",
    "attest_firewall": "Firewall and Perimeter Security Controls",
}

OPTIONAL_FIELDS = [
    "attest_bcp",
    "attest_pentest",
    "attest_cloud_sec",
    "attest_dlp",
    "attest_policy_framework",
    "attest_patch_mgmt",
    "attest_antimalware",
    "attest_cyber_insurance",
]

OPTIONAL_LABELS = {
    "attest_bcp": "Business Continuity Plan (BCP) Tested",
    "attest_pentest": "Penetration Testing Conducted",
    "attest_cloud_sec": "Cloud Security Controls Implemented",
    "attest_dlp": "Data Loss Prevention (DLP) Controls Deployed",
    "attest_policy_framework": "Cybersecurity Policy Framework Documented",
    "attest_patch_mgmt": "Patch Management Process Active",
    "attest_antimalware": "Anti-Malware / Anti-Virus Deployed",
    "attest_cyber_insurance": "Cyber Insurance Coverage Maintained",
}


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
                "transformationId": "attestation",
                "vendor": "WM - Cybersecurity Controls",
                "category": "wm-cybersecurity-controls"
            }
        }
    }


def evaluate(data):
    """Core evaluation logic for the attestation criteria key."""
    try:
        failed_mandatory = []
        passed_mandatory = []

        for field in MANDATORY_FIELDS:
            value = data.get(field, "None")
            label = MANDATORY_LABELS.get(field, field)
            if value == "Yes":
                passed_mandatory.append(label)
            else:
                failed_mandatory.append(label)

        optional_yes = []
        optional_no = []

        for field in OPTIONAL_FIELDS:
            value = data.get(field, "None")
            label = OPTIONAL_LABELS.get(field, field)
            if value == "Yes":
                optional_yes.append(label)
            else:
                optional_no.append(label)

        mandatory_total = len(MANDATORY_FIELDS)
        mandatory_passed_count = len(passed_mandatory)
        mandatory_failed_count = len(failed_mandatory)
        optional_total = len(OPTIONAL_FIELDS)
        optional_yes_count = len(optional_yes)
        optional_no_count = len(optional_no)

        all_mandatory_passed = mandatory_failed_count == 0

        score = 0
        if mandatory_total > 0:
            score = int((mandatory_passed_count * 100) / mandatory_total)

        return {
            "attestation": all_mandatory_passed,
            "mandatoryControlsPassed": mandatory_passed_count,
            "mandatoryControlsTotal": mandatory_total,
            "mandatoryControlsFailed": mandatory_failed_count,
            "failedMandatoryControls": failed_mandatory,
            "passedMandatoryControls": passed_mandatory,
            "optionalControlsAnsweredYes": optional_yes_count,
            "optionalControlsAnsweredNo": optional_no_count,
            "optionalControlsTotal": optional_total,
            "optionalControlsAnsweredYesList": optional_yes,
            "optionalControlsAnsweredNoList": optional_no,
            "mandatoryComplianceScoreInPercentage": score,
        }
    except Exception as e:
        return {"attestation": False, "error": str(e)}


def transform(input):
    criteriaKey = "attestation"
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

        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("All " + str(eval_result.get("mandatoryControlsTotal", 0)) + " mandatory cybersecurity controls are attested as 'Yes'.")
            pass_reasons.append("Mandatory compliance score: " + str(eval_result.get("mandatoryComplianceScoreInPercentage", 0)) + "%")
            opt_yes = eval_result.get("optionalControlsAnsweredYes", 0)
            opt_total = eval_result.get("optionalControlsTotal", 0)
            additional_findings.append("Optional controls answered 'Yes': " + str(opt_yes) + " of " + str(opt_total))
        else:
            failed = eval_result.get("failedMandatoryControls", [])
            fail_reasons.append(
                str(eval_result.get("mandatoryControlsFailed", 0)) + " mandatory control(s) not attested as 'Yes'."
            )
            fail_reasons.append("Mandatory compliance score: " + str(eval_result.get("mandatoryComplianceScoreInPercentage", 0)) + "%")
            for item in failed:
                fail_reasons.append("Missing mandatory control: " + item)
            recommendations.append("Ensure all mandatory controls are implemented and answered 'Yes' before resubmitting.")
            recommendations.append("Review failed controls and gather supporting evidence for each.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])

        opt_no_list = eval_result.get("optionalControlsAnsweredNoList", [])
        for item in opt_no_list:
            additional_findings.append("Optional control not yet implemented: " + item)

        result_dict = {criteriaKey: result_value}
        for k, v in extra_fields.items():
            result_dict[k] = v

        input_summary = {criteriaKey: result_value}
        for k, v in extra_fields.items():
            input_summary[k] = v

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
