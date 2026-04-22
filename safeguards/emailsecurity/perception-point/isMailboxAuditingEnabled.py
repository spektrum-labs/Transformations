"""
Transformation: isMailboxAuditingEnabled
Vendor: Perception Point  |  Category: emailsecurity
Evaluates: Assesses mailbox-level auditing by verifying scan records include
per-recipient data. Presence of recipient-level scan entries indicates a mailbox
audit trail is maintained within the Perception Point platform.
"""
import json
from datetime import datetime


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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMailboxAuditingEnabled", "vendor": "Perception Point", "category": "emailsecurity"}
        }
    }


def evaluate(data):
    try:
        scans = data.get("scans", [])
        if not isinstance(scans, list):
            scans = []
        scan_count = len(scans)
        scans_with_recipients = 0
        total_recipients = 0
        for scan in scans:
            if not isinstance(scan, dict):
                continue
            recipients = scan.get("recipients", [])
            if isinstance(recipients, list) and len(recipients) > 0:
                scans_with_recipients = scans_with_recipients + 1
                total_recipients = total_recipients + len(recipients)
        is_enabled = scan_count > 0 and scans_with_recipients > 0
        return {
            "isMailboxAuditingEnabled": is_enabled,
            "totalScans": scan_count,
            "scansWithRecipientData": scans_with_recipients,
            "totalRecipientEntries": total_recipients
        }
    except Exception as e:
        return {"isMailboxAuditingEnabled": False, "error": str(e)}


def transform(input):
    criteria_key = "isMailboxAuditingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(
                result={criteria_key: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )
        eval_result = evaluate(data)
        result_value = eval_result.get(criteria_key, False)
        extra_fields = {}
        for k in eval_result:
            if k != criteria_key and k != "error":
                extra_fields[k] = eval_result[k]
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append("Per-recipient scan records are present in Perception Point, confirming mailbox-level audit trail is maintained")
            r_count = extra_fields.get("scansWithRecipientData", 0)
            pass_reasons.append("Scan records containing recipient data: " + str(r_count))
        else:
            fail_reasons.append("No per-recipient scan records found; unable to confirm mailbox-level auditing is enabled")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure Perception Point is correctly integrated with your email provider and is receiving email traffic with recipient metadata")
        full_result = {criteria_key: result_value}
        for k in extra_fields:
            full_result[k] = extra_fields[k]
        return create_response(
            result=full_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=full_result,
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteria_key: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
