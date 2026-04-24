"""
Transformation: isSafeAttachmentsEnabled
Vendor: Perception Point  |  Category: emailsecurity
Evaluates: Confirms attachment/file sandboxing is active by checking for scans
containing attachment entries, verifying that safe attachment scanning is
operational in the Perception Point deployment.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSafeAttachmentsEnabled", "vendor": "Perception Point", "category": "emailsecurity"}
        }
    }


def evaluate(data):
    try:
        scans = data.get("scans", [])
        if not isinstance(scans, list):
            scans = []
        scan_count = len(scans)
        scans_with_attachments = 0
        for scan in scans:
            if not isinstance(scan, dict):
                continue
            attachments = scan.get("attachments", [])
            if isinstance(attachments, list) and len(attachments) > 0:
                scans_with_attachments = scans_with_attachments + 1
        is_enabled = scan_count > 0
        return {
            "isSafeAttachmentsEnabled": is_enabled,
            "totalScans": scan_count,
            "scansWithAttachments": scans_with_attachments
        }
    except Exception as e:
        return {"isSafeAttachmentsEnabled": False, "error": str(e)}


def transform(input):
    criteria_key = "isSafeAttachmentsEnabled"
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
            pass_reasons.append("Perception Point file sandboxing is active; safe attachment scanning is confirmed operational")
            att_count = extra_fields.get("scansWithAttachments", 0)
            if att_count > 0:
                additional_findings.append("Attachment data found in " + str(att_count) + " scan record(s)")
        else:
            fail_reasons.append("No scan records found to confirm safe attachment scanning is enabled")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify Perception Point is receiving and scanning email attachments")
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
