"""
Transformation: isSafeAttachmentsEnabled
Vendor: Proofpoint  |  Category: emailsecurity
Evaluates: Check if Attachment Defense (safe attachment sandboxing and scanning) feature
is enabled for the organization in Proofpoint Essentials (getOrgFeatures).
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
                "transformationId": "isSafeAttachmentsEnabled",
                "vendor": "Proofpoint",
                "category": "emailsecurity"
            }
        }
    }


def evaluate(data):
    try:
        if not isinstance(data, dict):
            return {"isSafeAttachmentsEnabled": False, "error": "Unexpected data format"}

        features = data.get("features", {})
        if not isinstance(features, dict):
            features = {}

        attachment_defense = data.get("attachment_defense", features.get("attachment_defense", None))
        safe_attachments = data.get("safe_attachments", features.get("safe_attachments", None))
        tap_attach = data.get("tap_attachment_defense", features.get("tap_attachment_defense", None))
        sandbox_enabled = data.get("sandbox_enabled", features.get("sandbox_enabled", None))

        is_enabled = (
            bool(attachment_defense) or
            bool(safe_attachments) or
            bool(tap_attach) or
            bool(sandbox_enabled)
        )

        return {
            "isSafeAttachmentsEnabled": is_enabled,
            "attachmentDefenseEnabled": attachment_defense,
            "safeAttachmentsEnabled": safe_attachments,
            "sandboxEnabled": sandbox_enabled
        }
    except Exception as e:
        return {"isSafeAttachmentsEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isSafeAttachmentsEnabled"
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
        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("Attachment Defense (safe attachments) is enabled in Proofpoint Essentials")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append("Attachment Defense (safe attachments) is not enabled")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Enable Attachment Defense in Proofpoint Essentials to sandbox and scan email attachments"
            )
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        input_summary = {criteriaKey: result_value}
        for k in extra_fields:
            input_summary[k] = extra_fields[k]
        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
